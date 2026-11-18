package com.gradial.core.oauth.obo;

import static org.junit.jupiter.api.Assertions.*;

import java.io.StringReader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.TreeMap;

import javax.jcr.Repository;
import javax.jcr.Session;
import javax.jcr.SimpleCredentials;
import javax.jcr.Value;
import javax.jcr.security.AccessControlEntry;
import javax.jcr.security.AccessControlManager;
import javax.jcr.security.AccessControlPolicy;
import javax.jcr.security.Privilege;

import org.apache.jackrabbit.api.JackrabbitSession;
import org.apache.jackrabbit.api.security.JackrabbitAccessControlEntry;
import org.apache.jackrabbit.api.security.JackrabbitAccessControlList;
import org.apache.jackrabbit.api.security.user.User;
import org.apache.jackrabbit.commons.cnd.CndImporter;
import org.apache.jackrabbit.oak.jcr.Jcr;
import org.apache.sling.jcr.repoinit.impl.JcrRepoInitOpsProcessorImpl;
import org.apache.sling.repoinit.parser.impl.RepoInitParserService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * The Java initializer must produce the same repository as the repoinit script it replaces (kept in test resources):
 * one Oak repository gets the script through real Sling repoinit, another gets the Java setup, and the service user,
 * node types and complete ACLs (principal, privileges, allow or deny, restrictions, order) are compared.
 */
class RepositoryInitEquivalenceTest {
    private static final String SLING_TYPES = "<sling='http://sling.apache.org/jcr/sling/1.0'>\n"
            + "[sling:Folder] > nt:folder\n - * (undefined) multiple\n - * (undefined)\n + * (nt:base) = sling:Folder version\n"
            + "[sling:OrderedFolder] > sling:Folder orderable\n + * (nt:base) = sling:OrderedFolder version\n";
    private static final String[] NODES = {"/var/gradial", "/var/gradial/obo", "/var/gradial/obo/grants", "/var/gradial/obo/consents"};
    private static final String[] ACL_PATHS = {"/var/gradial/obo", "/home/users", "/home/groups"};

    private static final class Repo {
        final Repository repository;
        final Session admin;

        Repo(String existingType, boolean preRelease, boolean serviceUserPresent, boolean administrators) throws Exception {
            repository = new Jcr().with(AemOak.security()).createRepository();
            admin = repository.login(new SimpleCredentials("admin", "admin".toCharArray()));
            CndImporter.registerNodeTypes(new StringReader(SLING_TYPES), admin);
            admin.getRootNode().addNode("var", "sling:Folder");
            if (administrators) ((JackrabbitSession) admin).getUserManager().createGroup("administrators");
            ((JackrabbitSession) admin).getUserManager().createUser("zz-seed", null);
            if (serviceUserPresent) ((JackrabbitSession) admin).getUserManager().createSystemUser("gradial-obo-state", "system/gradial");
            if (preRelease) {
                admin.getNode("/var").addNode("gradial", "nt:unstructured").addNode("obo", "nt:unstructured")
                        .addNode("grants", "nt:unstructured").addNode("ab", "oak:Unstructured");
            } else if (!existingType.isEmpty()) {
                admin.getNode("/var").addNode("gradial", existingType).addNode("zz-customer", "nt:folder");
            }
            admin.save();
        }

        Repo(String existingType, boolean preRelease, boolean serviceUserPresent) throws Exception {
            this(existingType, preRelease, serviceUserPresent, true);
        }

        void repoinit() throws Exception {
            new JcrRepoInitOpsProcessorImpl().apply(admin,
                    new RepoInitParserService().parse(new StringReader(RepositoryInitScriptTest.shippedScript())));
            admin.save();
        }

        void java() throws Exception {
            org.apache.sling.jcr.api.SlingRepository sling = org.mockito.Mockito.mock(org.apache.sling.jcr.api.SlingRepository.class);
            org.mockito.Mockito.when(sling.loginAdministrative(null))
                    .thenAnswer(call -> repository.login(new SimpleCredentials("admin", "admin".toCharArray())));
            assertTrue(new OboRepositoryInitializer().apply(sling));
            admin.refresh(false);
        }

        List<String> describe() throws Exception {
            List<String> out = new ArrayList<>();
            User user = (User) ((JackrabbitSession) admin).getUserManager().getAuthorizable("gradial-obo-state");
            assertNotNull(user);
            out.add("user system=" + user.isSystemUser() + " principal=" + user.getPrincipal().getName()
                    + " type=" + admin.getNode(user.getPath()).getPrimaryNodeType().getName());
            assertTrue(user.getPath().startsWith("/home/users/system/gradial/"), user.getPath());
            for (String path : NODES) {
                out.add(path + " " + (admin.nodeExists(path) ? admin.getNode(path).getPrimaryNodeType().getName() : "missing"));
            }
            AccessControlManager acm = admin.getAccessControlManager();
            for (String path : ACL_PATHS) {
                for (AccessControlPolicy policy : acm.getPolicies(path)) {
                    if (!(policy instanceof JackrabbitAccessControlList)) continue;
                    int i = 0;
                    for (AccessControlEntry e : ((JackrabbitAccessControlList) policy).getAccessControlEntries()) {
                        JackrabbitAccessControlEntry entry = (JackrabbitAccessControlEntry) e;
                        List<String> privileges = new ArrayList<>();
                        for (Privilege p : entry.getPrivileges()) privileges.add(p.getName());
                        Collections.sort(privileges);
                        TreeMap<String, String> restrictions = new TreeMap<>();
                        for (String name : entry.getRestrictionNames()) {
                            StringBuilder values = new StringBuilder();
                            for (Value v : entry.getRestrictions(name)) {
                                values.append(v.getType()).append(':').append(v.getString()).append(' ');
                            }
                            restrictions.put(name, values.toString().trim());
                        }
                        out.add(path + " #" + (i++) + " " + entry.getPrincipal().getName() + " "
                                + (entry.isAllow() ? "allow" : "deny") + " " + privileges + " " + restrictions);
                    }
                }
            }
            return out;
        }

        void close() { admin.logout(); }
    }

    private static void assertSame(Repo reference, Repo java, String why) throws Exception {
        List<String> expected = reference.describe();
        assertTrue(expected.size() > 8, "ACL entries were compared: " + expected);
        assertEquals(expected, java.describe(), why);
        System.out.println("equivalent (" + why + "): " + expected.size() + " items");
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "nt:folder", "sling:Folder", "sling:OrderedFolder", "nt:unstructured", "oak:Unstructured"})
    void javaSetupMatchesRepoinitOverEveryExistingVarGradial(String existingType) throws Exception {
        Repo reference = new Repo(existingType, false, false);
        Repo java = new Repo(existingType, false, false);
        try {
            reference.repoinit();
            java.java();
            assertSame(reference, java, "var/gradial=" + (existingType.isEmpty() ? "fresh" : existingType));
        } finally { reference.close(); java.close(); }
    }

    @Test
    void javaSetupMatchesRepoinitOverThePreReleaseLayout() throws Exception {
        Repo reference = new Repo("", true, false);
        Repo java = new Repo("", true, false);
        try {
            reference.repoinit();
            java.java();
            assertSame(reference, java, "pre-release layout");
        } finally { reference.close(); java.close(); }
    }

    @Test
    void javaSetupMatchesRepoinitWhenTheServiceUserAlreadyExists() throws Exception {
        Repo reference = new Repo("sling:Folder", false, true);
        Repo java = new Repo("sling:Folder", false, true);
        try {
            reference.repoinit();
            java.java();
            assertSame(reference, java, "service user present");
        } finally { reference.close(); java.close(); }
    }

    @Test
    void javaSetupAppliedTwiceMatchesRepoinitAppliedTwiceAndChangesNothing() throws Exception {
        Repo reference = new Repo("", false, false);
        Repo java = new Repo("", false, false);
        try {
            reference.repoinit();
            reference.repoinit();
            java.java();
            List<String> once = java.describe();
            java.java();
            assertEquals(once, java.describe(), "a second application changes no ACL");
            assertSame(reference, java, "applied twice");
        } finally { reference.close(); java.close(); }
    }

    @Test
    void withoutAnAdministratorsPrincipalBothFailAndSaveNothing() throws Exception {
        Repo reference = new Repo("", false, false, false);
        Repo java = new Repo("", false, false, false);
        try {
            assertThrows(Exception.class, reference::repoinit);
            org.apache.sling.jcr.api.SlingRepository sling = org.mockito.Mockito.mock(org.apache.sling.jcr.api.SlingRepository.class);
            org.mockito.Mockito.when(sling.loginAdministrative(null))
                    .thenAnswer(call -> java.repository.login(new SimpleCredentials("admin", "admin".toCharArray())));
            assertThrows(Exception.class, () -> new OboRepositoryInitializer().apply(sling));
            assertDoesNotThrow(() -> new OboRepositoryInitializer().processRepository(sling), "AEM still starts");
            reference.admin.refresh(false);
            java.admin.refresh(false);
            // Repoinit saves statement by statement and so leaves its earlier statements behind; the Java setup saves
            // once at the end and so leaves nothing, and the next start applies everything again.
            assertNull(((JackrabbitSession) java.admin).getUserManager().getAuthorizable("gradial-obo-state"));
            assertFalse(java.admin.nodeExists("/var/gradial"));
        } finally { reference.close(); java.close(); }
    }
}
