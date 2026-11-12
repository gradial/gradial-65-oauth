package com.gradial.core.oauth.scopes.impl;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;

import javax.jcr.Session;

import org.apache.jackrabbit.api.JackrabbitSession;
import org.apache.jackrabbit.api.security.user.Authorizable;
import org.apache.jackrabbit.api.security.user.User;
import org.apache.sling.jcr.api.SlingRepository;
import org.apache.sling.jcr.api.SlingRepositoryInitializer;
import org.apache.sling.jcr.repoinit.JcrRepoInitOpsProcessor;
import org.apache.sling.repoinit.parser.RepoInitParser;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.ConfigurationPolicy;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Creates the {@value DynamicScopeRegistrar#READER} service user that checks scope paths, applying the bundled
 * {@value #SCRIPT} with Sling's own {@link RepoInitParser} and {@link JcrRepoInitOpsProcessor} services.
 *
 * <p><b>Why Java, not a repoinit {@code .cfg.json}.</b> A {@code RepositoryInitializer~*.cfg.json} with
 * {@code create service user gradial-oauth-scope-reader} throws when a normal user or a group already has that ID
 * (jcr.repoinit 1.1.54 {@code UserVisitor.java:170-175}, "Existing user %s is not a service user."). At startup,
 * jcr.base runs every initializer before it registers {@code SlingRepository}, and any exception aborts that
 * registration ({@code AbstractSlingRepositoryManager.java:575-577} in jcr.base 3.2.0, "SlingRepository service
 * registration aborted"), so AEM would not start. Repoinit has no conditional or continue-on-error statement. This
 * class checks the ID first, leaves another account untouched, logs one ERROR and never throws.
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
    static final String SCRIPT = "gradial-oauth-scopes.repoinit";

    @Reference
    private RepoInitParser parser;
    @Reference
    private JcrRepoInitOpsProcessor processor;

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

    /** True when the script was applied; false when an account of another kind holds the ID. */
    boolean apply(SlingRepository repository) throws Exception {
        // The repository passed to an initializer is jcr.base's master repository, created for jcr.base's own
        // bundle (AbstractSlingRepositoryManager.java:568, create(this.bundleContext.getBundle())). Its
        // loginAdministrative checks allowLoginAdministrativeForBundle(usingBundle) for that bundle
        // (AbstractSlingRepository2.java:443-444), not for gradial.core, so no login-admin allow-list entry is
        // needed. Sling's own RepositoryInitializerFactory makes the same call (jcr.repoinit 1.1.54,
        // RepositoryInitializerFactory.java:126-128). loginService is impossible here: this creates the user that a
        // service login would need.
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
            try (Reader script = script()) {
                processor.apply(session, parser.parse(script));
            }
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

    static Reader script() throws IOException {
        InputStream stream = ScopeReaderRepositoryInitializer.class.getResourceAsStream(SCRIPT);
        if (stream == null) throw new IOException("Missing " + SCRIPT);
        return new InputStreamReader(stream, StandardCharsets.UTF_8);
    }
}
