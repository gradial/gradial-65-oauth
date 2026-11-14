package com.gradial.core.oauth.obo;

import static org.mockito.Mockito.*;

import java.util.Calendar;

import javax.jcr.InvalidItemStateException;
import javax.jcr.Node;
import javax.jcr.Repository;
import javax.jcr.Session;

import org.apache.jackrabbit.api.JackrabbitSession;
import org.apache.jackrabbit.api.security.user.User;
import org.apache.jackrabbit.api.security.user.UserManager;
import org.apache.sling.jcr.api.SlingRepository;
import org.apache.sling.testing.mock.jcr.MockJcr;
import org.mockito.AdditionalAnswers;

/** A real OboService over an in-memory repository with one ordinary AEM user. */
final class OboFixture {
    static final String USER = "ordinary-author";
    static final String CLIENT = "gradial";
    static final String SECRET = "a-long-random-client-secret";
    static final String REDIRECT = "https://app.gradial.com/aem/callback";
    static final String STATE = "0123456789abcdef0123456789abcdef";

    final Repository storage;
    final User user = mock(User.class);
    final UserManager users = mock(UserManager.class);
    final OboConfiguration config = mock(OboConfiguration.class);
    final OboService service = new OboService();
    /** Runs once inside the next save and then fails it, as Oak does when a concurrent writer wins. */
    volatile Runnable conflictOnNextSave;
    /** Oak mode only: runs once inside the next save, before it is applied, as a concurrent writer's whole request. */
    volatile Runnable beforeNextSave;
    private final boolean oak;

    OboFixture() throws Exception { this(false); }

    /** With {@code oak}, storage is a real Oak repository: sessions keep their own snapshot and saves conflict for real. */
    OboFixture(boolean oak) throws Exception {
        this.oak = oak;
        storage = oak ? new org.apache.jackrabbit.oak.jcr.Jcr().with(AemOak.security()).createRepository() : MockJcr.newRepository();
        Session session = open();
        Node root = session.getRootNode();
        for (String path : new String[] {OboService.ROOT, OboService.CONSENTS}) {
            Node node = root;
            for (String segment : path.substring(1).split("/")) {
                node = node.hasNode(segment) ? node.getNode(segment) : node.addNode(segment, "nt:unstructured");
            }
        }
        String userPath;
        if (oak) {
            // A real account: Oak owns /home/users and stamps jcr:created itself.
            userPath = ((JackrabbitSession) session).getUserManager().createUser(USER, "ordinary-author-password").getPath();
        } else {
            root.addNode("home", "nt:unstructured").addNode("users", "nt:unstructured")
                    .addNode(USER, "nt:unstructured").setProperty("jcr:created", Calendar.getInstance());
            userPath = "/home/users/" + USER;
        }
        session.save();
        session.logout();
        when(user.getPath()).thenReturn(userPath);
        when(users.getAuthorizable(USER)).thenReturn(user);
        SlingRepository repository = mock(SlingRepository.class);
        when(repository.loginService("obo", null)).thenAnswer(invocation -> {
            Session real = open();
            JackrabbitSession delegated = mock(JackrabbitSession.class, AdditionalAnswers.delegatesTo(real));
            doReturn(users).when(delegated).getUserManager();
            // The in-memory repository applies changes immediately, so discarding is a no-op. Oak really discards.
            if (!oak) doNothing().when(delegated).refresh(anyBoolean());
            doAnswer(save -> {
                Runnable before = beforeNextSave;
                if (before != null) {
                    beforeNextSave = null;
                    before.run();
                }
                Runnable conflict = conflictOnNextSave;
                if (conflict != null) {
                    conflictOnNextSave = null;
                    conflict.run();
                    throw new InvalidItemStateException("concurrent change");
                }
                real.save();
                return null;
            }).when(delegated).save();
            return delegated;
        });
        java.lang.reflect.Field field = OboService.class.getDeclaredField("repository");
        field.setAccessible(true);
        field.set(service, repository);
        when(config.enabled()).thenReturn(true);
        when(config.clientId()).thenReturn(CLIENT);
        when(config.clientSecretSha256()).thenReturn(OboService.hash(SECRET));
        when(config.publicOrigin()).thenReturn("https://author.example.com");
        when(config.redirectUris()).thenReturn(new String[] {REDIRECT});
        when(config.accessTokenSeconds()).thenReturn(300);
        when(config.grantSeconds()).thenReturn(86400);
        service.activate(config, java.util.Collections.emptyMap());
    }

    /** A new session on the storage repository (an administrator on Oak, which has no anonymous write access). */
    Session open() throws Exception {
        return oak ? storage.login(new javax.jcr.SimpleCredentials("admin", "admin".toCharArray())) : storage.login();
    }

    static String idOf(String token) { return token.substring(4, token.indexOf('.')); }

    /** The login module's per-request validation, over the fixture repository. */
    String authenticate(String access) throws Exception {
        Session session = open();
        try { return service.validateAccess(OboService.records(session), users, access); } finally { session.logout(); }
    }

    static int count(Node node) throws Exception {
        int total = 0;
        for (javax.jcr.NodeIterator it = node.getNodes(); it.hasNext();) { it.nextNode(); total++; }
        return total;
    }

    /** Number of leaf records under a bucketed tree (records sit at depth 2: bucket, user folder, record). */
    static int records(Repository storage, String root, int depth) throws Exception {
        Session session = storage.login();
        try { return records(session.getNode(root), depth); } finally { session.logout(); }
    }

    private static int records(Node node, int depth) throws Exception {
        int total = 0;
        for (javax.jcr.NodeIterator it = node.getNodes(); it.hasNext();) {
            Node child = it.nextNode();
            total += depth == 0 ? 1 : records(child, depth - 1);
        }
        return total;
    }
}
