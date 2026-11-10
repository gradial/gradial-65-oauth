package com.gradial.core.oauth.obo;

import static org.junit.jupiter.api.Assertions.*;

import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Iterator;

import javax.jcr.Node;
import javax.jcr.Repository;
import javax.jcr.Session;
import javax.jcr.SimpleCredentials;

import org.apache.jackrabbit.api.JackrabbitSession;
import org.apache.jackrabbit.api.security.user.Group;
import org.apache.jackrabbit.api.security.user.User;
import org.apache.jackrabbit.api.security.user.UserManager;
import org.apache.jackrabbit.commons.cnd.CndImporter;
import org.apache.jackrabbit.oak.jcr.Jcr;
import org.apache.sling.jcr.repoinit.impl.JcrRepoInitOpsProcessorImpl;
import org.apache.sling.repoinit.parser.impl.RepoInitParserService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.Test;

/**
 * Runs the shipped repoinit script with the Oak and Sling repoinit versions of AEM 6.5 SP25. A failing
 * repoinit script stops SlingRepository, so the script must apply cleanly to every state a customer
 * repository can already be in, and to itself.
 */
class RepositoryInitScriptTest {
    private static final String SLING_TYPES = "<sling='http://sling.apache.org/jcr/sling/1.0'>\n"
            + "[sling:Folder] > nt:folder\n - * (undefined) multiple\n - * (undefined)\n + * (nt:base) = sling:Folder version\n"
            + "[sling:OrderedFolder] > sling:Folder orderable\n + * (nt:base) = sling:OrderedFolder version\n";

    private Repository repository;
    private Session admin;

    @BeforeEach
    void repository() throws Exception {
        repository = new Jcr().with(AemOak.security()).createRepository();
        admin = repository.login(new SimpleCredentials("admin", "admin".toCharArray()));
        CndImporter.registerNodeTypes(new StringReader(SLING_TYPES), admin);
        admin.getRootNode().addNode("var", "sling:Folder");
        // AEM always has /home/users and /home/groups; an empty Oak repository has them once an authorizable exists.
        ((JackrabbitSession) admin).getUserManager().createGroup("administrators");
        ((JackrabbitSession) admin).getUserManager().createUser("zz-seed", null);
        admin.save();
    }

    @AfterEach
    void close() { admin.logout(); }

    static String shippedScript() throws Exception {
        String json = new String(Files.readAllBytes(Paths.get("../ui.config/src/main/content/jcr_root/apps/gradial/osgiconfig/"
                + "config.author/org.apache.sling.jcr.repoinit.RepositoryInitializer~gradial-obo.cfg.json")), StandardCharsets.UTF_8);
        String body = json.substring(json.indexOf("[") + 1, json.lastIndexOf("]")).trim();
        return body.substring(1, body.length() - 1).replace("\\n", "\n").replace("\\\"", "\"");
    }

    private void apply(String script) throws Exception {
        new JcrRepoInitOpsProcessorImpl().apply(admin, new RepoInitParserService().parse(new StringReader(script)));
        admin.save();
    }

    private void storeAcceptsRecords() throws Exception {
        for (String parent : new String[] {OboService.ROOT, OboService.CONSENTS}) {
            Node bucket = admin.getNode(parent).addNode("ab", OboService.CONTAINER);
            bucket.addNode("0123456789abcdef", OboService.CONTAINER).addNode("record", OboService.CONTAINER);
        }
        admin.save();
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "nt:folder", "sling:Folder", "sling:OrderedFolder", "nt:unstructured", "oak:Unstructured"})
    void appliesTwiceOverAnyExistingVarGradial(String existingType) throws Exception {
        if (!existingType.isEmpty()) {
            admin.getNode("/var").addNode("gradial", existingType).addNode("zz-customer", "nt:folder");
            admin.save();
        }
        apply(shippedScript());
        apply(shippedScript());
        storeAcceptsRecords();
        assertTrue(((JackrabbitSession) admin).getUserManager().getAuthorizable("gradial-obo-state") instanceof User);
        if (!existingType.isEmpty()) {
            assertEquals(existingType, admin.getNode("/var/gradial").getPrimaryNodeType().getName(), "existing node type is untouched");
            assertTrue(admin.nodeExists("/var/gradial/zz-customer"), "existing content is untouched");
        }
    }

    @Test
    void appliesOverThePreReleaseStoreLayout() throws Exception {
        Node obo = admin.getNode("/var").addNode("gradial", "nt:unstructured").addNode("obo", "nt:unstructured");
        obo.addNode("grants", "nt:unstructured").addNode("ab", "oak:Unstructured");
        admin.save();
        apply(shippedScript());
        assertTrue(admin.nodeExists("/var/gradial/obo/grants/ab"), "pre-release records are left for cleanup");
        assertTrue(admin.nodeExists(OboService.CONSENTS));
    }

    @Test
    void thePreviousScriptFailedWhenVarGradialWasAFolder() throws Exception {
        admin.getNode("/var").addNode("gradial", "nt:folder");
        admin.save();
        assertThrows(Exception.class, () -> apply("create path (oak:Unstructured) /var/gradial/obo/grants"),
                "regression guard: oak:Unstructured cannot be a child of nt:folder");
        admin.refresh(false);
        apply(shippedScript());
    }

    @Test
    void everyoneIsLockedOutButAdministratorsAndTheServiceUserAreNot() throws Exception {
        UserManager users = ((JackrabbitSession) admin).getUserManager();
        users.createUser("zz-author", "zz-author-password");
        users.createUser("zz-admin", "zz-admin-password");
        ((Group) users.getAuthorizable("administrators")).addMember(users.getAuthorizable("zz-admin"));
        admin.save();
        apply(shippedScript());
        storeAcceptsRecords();

        Session author = repository.login(new SimpleCredentials("zz-author", "zz-author-password".toCharArray()));
        try { assertFalse(author.nodeExists(OboService.STORE)); } finally { author.logout(); }

        Session administrator = repository.login(new SimpleCredentials("zz-admin", "zz-admin-password".toCharArray()));
        try {
            assertTrue(administrator.nodeExists(OboService.ROOT + "/ab/0123456789abcdef/record"));
            administrator.getNode(OboService.ROOT + "/ab").remove();
            administrator.save();
        } finally { administrator.logout(); }

        Session service = admin.impersonate(new SimpleCredentials("gradial-obo-state", new char[0]));
        try {
            Node consent = service.getNode(OboService.CONSENTS + "/ab/0123456789abcdef/record");
            consent.setProperty("expires", 1L);
            service.save();
        } finally { service.logout(); }
    }

    @Test
    void theServiceUserSeesAdministratorsMembershipHeldInOverflowMemberLists() throws Exception {
        UserManager users = ((JackrabbitSession) admin).getUserManager();
        Group administrators = (Group) users.getAuthorizable("administrators");
        // Oak moves members past the first 100 into rep:membersList child nodes.
        for (int i = 0; i < 150; i++) administrators.addMember(users.createUser("zz-member-" + i, null));
        admin.save();
        assertTrue(admin.nodeExists(administrators.getPath() + "/rep:membersList"), "fixture must use the overflow list");
        apply(shippedScript());

        Session service = admin.impersonate(new SimpleCredentials("gradial-obo-state", new char[0]));
        try {
            User overflow = (User) ((JackrabbitSession) service).getUserManager().getAuthorizable("zz-member-149");
            boolean member = false;
            for (Iterator<Group> groups = overflow.memberOf(); groups.hasNext();) {
                member |= "administrators".equals(groups.next().getID());
            }
            assertTrue(member, "the consent-time administrator check must see overflow members");
            assertFalse(service.propertyExists(overflow.getPath() + "/rep:password"), "password hashes stay unreadable");
        } finally { service.logout(); }
    }
}
