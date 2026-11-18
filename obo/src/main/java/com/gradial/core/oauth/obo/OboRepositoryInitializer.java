package com.gradial.core.oauth.obo;

import java.security.Principal;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.jcr.Node;
import javax.jcr.PropertyType;
import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.Value;
import javax.jcr.security.AccessControlManager;
import javax.jcr.security.AccessControlPolicy;
import javax.jcr.security.AccessControlPolicyIterator;
import javax.jcr.security.Privilege;

import org.apache.jackrabbit.api.JackrabbitSession;
import org.apache.jackrabbit.api.security.JackrabbitAccessControlList;
import org.apache.jackrabbit.api.security.principal.PrincipalManager;
import org.apache.jackrabbit.api.security.user.Authorizable;
import org.apache.jackrabbit.api.security.user.User;
import org.apache.jackrabbit.api.security.user.UserManager;
import org.apache.sling.jcr.api.SlingRepository;
import org.apache.sling.jcr.api.SlingRepositoryInitializer;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.ConfigurationPolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Sets up the {@value #SERVICE_USER} service user and the delegation store through the JCR and Jackrabbit APIs. The
 * statements it applies are the Sling repoinit script {@code gradial-obo.repoinit} (kept under the test resources as
 * the reference; a test proves both produce the same repository).
 *
 * <p>Why Java and not a repoinit {@code .cfg.json}: an existing normal user or group with that ID makes
 * {@code create service user} throw (UserVisitor.checkUserType), and AbstractSlingRepositoryManager then aborts
 * SlingRepository registration, so AEM would not start. This initializer instead leaves such an account untouched,
 * applies nothing, logs one ERROR and never throws, so AEM always starts. Delegation then stays inert: the service
 * mapping refuses a non-system user, so no consent or token request can succeed.
 *
 * <p>Why not Sling's repoinit services either: the AEM 6.5 API controller
 * (com.adobe.granite.apicontroller.FilterResolverHookFactory) refuses to wire customer bundles to
 * {@code org.apache.sling.repoinit.parser} (AEM 6.5 LTS does not), which would leave gradial.obo unresolved on
 * AEM 6.5. This class therefore imports only {@code javax.jcr} and {@code org.apache.jackrabbit.api}.
 *
 * <p>Runs only when its configuration exists, which this package ships for Author only.
 */
@Component(service = SlingRepositoryInitializer.class, configurationPolicy = ConfigurationPolicy.REQUIRE)
public class OboRepositoryInitializer implements SlingRepositoryInitializer {
    private static final Logger LOG = LoggerFactory.getLogger(OboRepositoryInitializer.class);
    static final String SERVICE_USER = "gradial-obo-state";
    private static final String FOLDER = "sling:Folder";
    private static final String OBO = "/var/gradial/obo";

    @Override
    public void processRepository(SlingRepository repository) {
        try {
            apply(repository);
        } catch (Exception | LinkageError e) {
            LOG.error("Could not set up user delegation ({}); delegation stays unavailable. AEM starts normally.",
                    SERVICE_USER, e);
        }
    }

    /** True when the setup was applied; false when an account of another kind holds the ID. */
    boolean apply(SlingRepository repository) throws Exception {
        // An admin session is what repoinit's own initializer uses for the same statements.
        Session session = repository.loginAdministrative(null);
        try {
            UserManager users = ((JackrabbitSession) session).getUserManager();
            Authorizable existing = users.getAuthorizable(SERVICE_USER);
            if (existing != null && (existing.isGroup() || !((User) existing).isSystemUser())) {
                LOG.error("The ID {} already belongs to a {} that is not this package's service user. It was left "
                        + "unchanged and nothing was set up; user delegation stays unavailable. Rename that account to "
                        + "enable it.", SERVICE_USER, existing.isGroup() ? "group" : "user");
                return false;
            }
            setUp(session);
            session.save();
            return true;
        } finally {
            session.logout();
        }
    }

    private static void setUp(Session session) throws RepositoryException {
        JackrabbitSession jackrabbit = (JackrabbitSession) session;
        UserManager users = jackrabbit.getUserManager();
        PrincipalManager principals = jackrabbit.getPrincipalManager();

        // create service user gradial-obo-state with path system/gradial
        Authorizable existing = users.getAuthorizable(SERVICE_USER);
        User service = existing != null ? (User) existing : users.createSystemUser(SERVICE_USER, "system/gradial");

        // create path (sling:Folder) /var/gradial/obo/grants and /consents
        createPath(session, OBO + "/grants");
        createPath(session, OBO + "/consents");

        Privilege[] readWrite = privileges(session, "jcr:read", "rep:write");
        Privilege[] read = privileges(session, "jcr:read");
        Map<String, Value> none = Collections.emptyMap();

        // set ACL for everyone: deny jcr:read,rep:write on /var/gradial/obo
        Principal everyone = principals.getEveryone();
        JackrabbitAccessControlList obo = list(session, OBO);
        add(obo, everyone, readWrite, false, none, none());
        write(session, OBO, obo);

        // set ACL for administrators: allow jcr:read,rep:write on /var/gradial/obo
        Principal administrators = principals.getPrincipal("administrators");
        if (administrators == null) {
            // As in repoinit, a missing principal fails the whole setup before anything is saved.
            throw new RepositoryException("Principal administrators not found");
        }
        obo = list(session, OBO);
        add(obo, administrators, readWrite, true, none, none());
        write(session, OBO, obo);

        // set ACL for gradial-obo-state
        Principal state = service.getPrincipal();
        obo = list(session, OBO);
        add(obo, state, readWrite, true, none, none());
        write(session, OBO, obo);

        JackrabbitAccessControlList home = list(session, "/home/users");
        add(home, state, read, true, none,
                names(session, "rep:ntNames", "rep:AuthorizableFolder", "rep:User"));
        add(home, state, read, false, none, names(session, "rep:itemNames", "rep:password"));
        write(session, "/home/users", home);

        JackrabbitAccessControlList groups = list(session, "/home/groups");
        add(groups, state, read, true, none, names(session, "rep:ntNames", "rep:AuthorizableFolder", "rep:Group",
                "rep:MemberReferencesList", "rep:MemberReferences"));
        write(session, "/home/groups", groups);
    }

    /** Creates each missing segment as sling:Folder and leaves existing nodes untouched. */
    private static void createPath(Session session, String path) throws RepositoryException {
        Node node = session.getRootNode();
        for (String name : path.substring(1).split("/")) {
            node = node.hasNode(name) ? node.getNode(name) : node.addNode(name, FOLDER);
        }
    }

    private static Privilege[] privileges(Session session, String... names) throws RepositoryException {
        AccessControlManager acm = session.getAccessControlManager();
        Privilege[] out = new Privilege[names.length];
        for (int i = 0; i < names.length; i++) out[i] = acm.privilegeFromName(names[i]);
        return out;
    }

    private static Map<String, Value[]> none() {
        return Collections.emptyMap();
    }

    private static Map<String, Value[]> names(Session session, String restriction, String... values)
            throws RepositoryException {
        Value[] out = new Value[values.length];
        for (int i = 0; i < values.length; i++) out[i] = session.getValueFactory().createValue(values[i], PropertyType.NAME);
        Map<String, Value[]> map = new HashMap<>();
        map.put(restriction, out);
        return map;
    }

    /** The node's existing access control list, else the applicable one. */
    private static JackrabbitAccessControlList list(Session session, String path) throws RepositoryException {
        AccessControlManager acm = session.getAccessControlManager();
        for (AccessControlPolicy policy : acm.getPolicies(path)) {
            if (policy instanceof JackrabbitAccessControlList) return (JackrabbitAccessControlList) policy;
        }
        for (AccessControlPolicyIterator it = acm.getApplicablePolicies(path); it.hasNext();) {
            AccessControlPolicy policy = it.nextAccessControlPolicy();
            if (policy instanceof JackrabbitAccessControlList) return (JackrabbitAccessControlList) policy;
        }
        throw new RepositoryException("No access control list can be set on " + path);
    }

    /** Adds an entry; the list itself ignores one that is already present. */
    private static void add(JackrabbitAccessControlList acl, Principal principal, Privilege[] privileges,
            boolean allow, Map<String, Value> single, Map<String, Value[]> multi) throws RepositoryException {
        acl.addEntry(principal, privileges, allow, single, multi);
    }

    private static void write(Session session, String path, JackrabbitAccessControlList acl) throws RepositoryException {
        session.getAccessControlManager().setPolicy(path, acl);
    }
}
