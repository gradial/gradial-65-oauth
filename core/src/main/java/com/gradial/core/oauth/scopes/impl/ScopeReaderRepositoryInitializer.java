package com.gradial.core.oauth.scopes.impl;

import javax.jcr.Session;
import javax.jcr.security.AccessControlManager;
import javax.jcr.security.AccessControlPolicy;
import javax.jcr.security.AccessControlPolicyIterator;
import javax.jcr.security.Privilege;

import org.apache.jackrabbit.api.JackrabbitSession;
import org.apache.jackrabbit.api.security.JackrabbitAccessControlList;
import org.apache.jackrabbit.api.security.user.Authorizable;
import org.apache.jackrabbit.api.security.user.User;
import org.apache.jackrabbit.api.security.user.UserManager;
import org.apache.sling.jcr.api.SlingRepository;
import org.apache.sling.jcr.api.SlingRepositoryInitializer;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.ConfigurationPolicy;
import org.osgi.service.component.annotations.Deactivate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Creates the {@value DynamicScopeRegistrar#READER} service user that checks scope paths, applying the bundled
 * with the JCR and Jackrabbit APIs. The result is what these repoinit statements would produce:
 * <pre>
 * create service user gradial-oauth-scope-reader with path system/gradial
 * set ACL for gradial-oauth-scope-reader
 *   allow rep:readNodes on /
 * end
 * </pre>
 *
 * <p><b>Why Java, not a repoinit {@code .cfg.json}.</b> A {@code RepositoryInitializer~*.cfg.json} with
 * {@code create service user gradial-oauth-scope-reader} throws when a normal user or a group already has that ID
 * (jcr.repoinit 1.1.54 {@code UserVisitor.java:170-175}, "Existing user %s is not a service user."). At startup,
 * jcr.base runs every initializer before it registers {@code SlingRepository}, and any exception aborts that
 * registration ({@code AbstractSlingRepositoryManager.java:575-577} in jcr.base 3.2.0, "SlingRepository service
 * registration aborted"), so AEM would not start. Repoinit has no conditional or continue-on-error statement. This
 * class checks the ID first, leaves another account untouched, logs one ERROR and never throws.
 *
 * <p><b>Why not Sling's repoinit services.</b> AEM 6.5's API controller
 * ({@code com.adobe.granite.apicontroller.FilterResolverHookFactory}) refuses to wire a customer bundle to
 * {@code org.apache.sling.repoinit.parser}, so a component that used {@code RepoInitParser} could not link there
 * and the user would never be created. AEM as 6.5 LTS does not refuse it, but the same code must work on both, so
 * this class imports only {@code javax.jcr} and {@code org.apache.jackrabbit.api} packages.
 *
 * <p>An initializer registered after the repository is up runs at once, against the same master repository
 * ({@code AbstractSlingRepositoryManager.java:486-492}), so a package install sets the user up without a restart.
 * When the user is in place it registers {@link ScopeReaderReady}, so scope registrars that activated before the
 * user existed check their paths at that moment.
 *
 * <p>Enabled only by {@code com.gradial.core.oauth.scopes.impl.ScopeReaderRepositoryInitializer.cfg.json}, an
 * empty configuration this package ships in {@code config.author} ({@code configurationPolicy=REQUIRE}), so it
 * runs on Author only.
 */
@Component(service = SlingRepositoryInitializer.class, configurationPolicy = ConfigurationPolicy.REQUIRE)
public class ScopeReaderRepositoryInitializer implements SlingRepositoryInitializer {
    private static final Logger LOG = LoggerFactory.getLogger(ScopeReaderRepositoryInitializer.class);
    private static final String USER_PATH = "system/gradial";
    private static final String PRIVILEGE = "rep:readNodes";

    private BundleContext bundleContext;
    private ServiceRegistration<ScopeReaderReady> ready;

    @Activate
    void activate(BundleContext context) {
        this.bundleContext = context;
    }

    @Deactivate
    synchronized void deactivate() {
        if (ready != null) {
            try {
                ready.unregister();
            } catch (IllegalStateException alreadyGone) {
                // The bundle is stopping and the framework already removed it.
            }
            ready = null;
        }
        bundleContext = null;
    }

    @Override
    public void processRepository(SlingRepository repository) {
        try {
            if (apply(repository)) announce();
        } catch (Exception | LinkageError e) {
            LOG.error("Could not set up the {} service user; OAuth scopes register without checking their paths. AEM "
                    + "starts normally.", DynamicScopeRegistrar.READER, e);
        }
    }

    /** True when the user and ACL are in place; false when an account of another kind holds the ID. */
    boolean apply(SlingRepository repository) throws Exception {
        // The repository passed to an initializer is jcr.base's master repository, created for jcr.base's own
        // bundle (AbstractSlingRepositoryManager.java:568, create(this.bundleContext.getBundle())). Its
        // loginAdministrative checks allowLoginAdministrativeForBundle(usingBundle) for that bundle
        // (AbstractSlingRepository2.java:443-444), not for gradial.core, so no login-admin allow-list entry is
        // needed. loginService is impossible here: this creates the user that a service login would need.
        @SuppressWarnings("deprecation")
        Session session = repository.loginAdministrative(null);
        try {
            Authorizable existing = ((JackrabbitSession) session).getUserManager().getAuthorizable(DynamicScopeRegistrar.READER);
            if (existing != null && (existing.isGroup() || !((User) existing).isSystemUser())) {
                LOG.error("The ID {} already belongs to a {} that is not this package's service user. It was left "
                        + "unchanged and nothing was set up; OAuth scopes register without checking their paths. Rename "
                        + "that account to enable the check.", DynamicScopeRegistrar.READER, existing.isGroup() ? "group" : "user");
                return false;
            }
            UserManager users = ((JackrabbitSession) session).getUserManager();
            User reader = existing != null ? (User) existing : users.createSystemUser(DynamicScopeRegistrar.READER, USER_PATH);
            allowReadNodesOnRoot(session, reader);
            session.save();
            return true;
        } finally {
            session.logout();
        }
    }

    /** Tells scope registrars that the reader exists. */
    private synchronized void announce() {
        if (ready == null && bundleContext != null) {
            ready = bundleContext.registerService(ScopeReaderReady.class, new ScopeReaderReady() { }, null);
        }
    }

    /** {@code allow rep:readNodes on /} for the user; writes the policy only when the entry is new. */
    private static void allowReadNodesOnRoot(Session session, User reader) throws Exception {
        AccessControlManager acm = session.getAccessControlManager();
        JackrabbitAccessControlList acl = null;
        for (AccessControlPolicy policy : acm.getPolicies("/")) {
            if (policy instanceof JackrabbitAccessControlList) acl = (JackrabbitAccessControlList) policy;
        }
        if (acl == null) {
            AccessControlPolicyIterator applicable = acm.getApplicablePolicies("/");
            while (acl == null && applicable.hasNext()) {
                AccessControlPolicy policy = applicable.nextAccessControlPolicy();
                if (policy instanceof JackrabbitAccessControlList) acl = (JackrabbitAccessControlList) policy;
            }
        }
        if (acl == null) throw new javax.jcr.security.AccessControlException("No editable access control list on /");
        if (acl.addEntry(reader.getPrincipal(), new Privilege[] {acm.privilegeFromName(PRIVILEGE)}, true)) {
            acm.setPolicy("/", acl);
        }
    }
}
