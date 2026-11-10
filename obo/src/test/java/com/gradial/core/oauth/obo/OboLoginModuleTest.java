package com.gradial.core.oauth.obo;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.security.Principal;
import java.util.Collections;
import java.util.HashMap;
import java.util.Set;
import java.util.stream.Collectors;

import javax.jcr.Credentials;
import javax.jcr.Node;
import javax.jcr.Repository;
import javax.jcr.Session;
import javax.jcr.SimpleCredentials;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;

import org.apache.jackrabbit.api.JackrabbitSession;
import org.apache.jackrabbit.api.security.user.Group;
import org.apache.jackrabbit.api.security.user.UserManager;
import org.apache.jackrabbit.oak.Oak;
import org.apache.jackrabbit.oak.api.AuthInfo;
import org.apache.jackrabbit.oak.api.ContentRepository;
import org.apache.jackrabbit.oak.jcr.Jcr;
import org.apache.jackrabbit.oak.spi.security.SecurityProvider;
import org.apache.jackrabbit.oak.spi.security.authentication.callback.CredentialsCallback;
import org.apache.jackrabbit.oak.spi.security.authentication.callback.RepositoryCallback;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Drives the login module against a real Oak repository: AbstractLoginModule's system root, Oak's
 * user manager and principal provider, and the record written for a grant.
 */
class OboLoginModuleTest {
    private static final String USER = "zz-writer";
    private SecurityProvider security;
    private ContentRepository content;
    private Session admin;
    private OboService service;
    private OboConfiguration config;

    @BeforeEach
    void repository() throws Exception {
        security = AemOak.security();
        Jcr jcr = new Jcr(new Oak()).with(security);
        content = jcr.createContentRepository();
        Repository repository = jcr.createRepository();
        admin = repository.login(new SimpleCredentials("admin", "admin".toCharArray()));
        UserManager users = ((JackrabbitSession) admin).getUserManager();
        users.createUser(USER, null);
        users.createGroup("administrators");
        users.createGroup("restricted-authors").addMember(users.getAuthorizable(USER));
        Node node = admin.getRootNode();
        for (String segment : OboService.ROOT.substring(1).split("/")) {
            node = node.hasNode(segment) ? node.getNode(segment) : node.addNode(segment, "oak:Unstructured");
        }
        admin.save();
        config = mock(OboConfiguration.class);
        when(config.enabled()).thenReturn(true);
        when(config.clientId()).thenReturn("gradial");
        when(config.clientSecretSha256()).thenReturn(OboService.hash("secret"));
        when(config.publicOrigin()).thenReturn("https://author.example.com");
        when(config.redirectUris()).thenReturn(new String[] {"https://app.example.com/cb"});
        when(config.accessTokenSeconds()).thenReturn(300);
        when(config.grantSeconds()).thenReturn(86400);
        service = new OboService();
        service.activate(config);
    }

    @AfterEach
    void close() { admin.logout(); }

    /** Writes a live grant for USER, as the token endpoint would, and returns its access credential. */
    private String grant() throws Exception {
        String id = OboService.recordId(USER);
        String access = "goa_" + id + "." + OboService.random();
        Node user = admin.getNode(((JackrabbitSession) admin).getUserManager().getAuthorizable(USER).getPath());
        Node bucket = admin.getNode(OboService.ROOT);
        bucket = bucket.hasNode(id.substring(0, 2)) ? bucket.getNode(id.substring(0, 2)) : bucket.addNode(id.substring(0, 2), "oak:Unstructured");
        Node folder = bucket.hasNode(id.substring(0, 16)) ? bucket.getNode(id.substring(0, 16)) : bucket.addNode(id.substring(0, 16), "oak:Unstructured");
        Node grant = folder.addNode(id, "oak:Unstructured");
        grant.setProperty("userId", USER);
        grant.setProperty("userIdentifier", user.getIdentifier() + ":" + user.getProperty("jcr:created").getDate().getTimeInMillis());
        grant.setProperty("configurationHash", OboService.hash("gradial\n" + OboService.hash("secret")));
        grant.setProperty("accessHash", OboService.hash(access));
        grant.setProperty("accessExpires", OboService.now() + 60000);
        grant.setProperty("created", OboService.now());
        grant.setProperty("expires", OboService.now() + 3600000);
        admin.save();
        return access;
    }

    private OboLoginModuleFactory.DelegationLoginModule module(Subject subject, Credentials credentials) {
        CallbackHandler callbacks = values -> {
            for (Callback callback : values) {
                if (callback instanceof CredentialsCallback) {
                    ((CredentialsCallback) callback).setCredentials(credentials);
                } else if (callback instanceof RepositoryCallback) {
                    RepositoryCallback target = (RepositoryCallback) callback;
                    target.setContentRepository(content);
                    target.setSecurityProvider(security);
                    target.setWorkspaceName(admin.getWorkspace().getName());
                } else {
                    throw new UnsupportedCallbackException(callback);
                }
            }
        };
        OboLoginModuleFactory.DelegationLoginModule module = new OboLoginModuleFactory.DelegationLoginModule(service);
        module.initialize(subject, callbacks, new HashMap<String, Object>(), Collections.<String, Object>emptyMap());
        return module;
    }

    private static Set<String> names(Set<? extends Principal> principals) {
        return principals.stream().map(Principal::getName).collect(Collectors.toSet());
    }

    @Test
    void theDelegatedUserGetsTheirOwnPrincipalsAndTheSessionIsStampedWithTheCredential() throws Exception {
        String access = grant();
        Subject subject = new Subject();
        OboLoginModuleFactory.DelegationLoginModule module = module(subject, new OboCredentials(access));
        assertTrue(module.login());
        assertTrue(module.commit());
        AuthInfo info = subject.getPublicCredentials(AuthInfo.class).iterator().next();
        assertEquals(USER, info.getUserID());
        assertEquals(OboService.hash(access), info.getAttribute(OboLoginModuleFactory.ACCESS_ATTRIBUTE));
        assertTrue(names(subject.getPrincipals()).containsAll(Set.of(USER, "restricted-authors", "everyone")));
        assertFalse(names(subject.getPrincipals()).contains("admin"));
        assertTrue(module.logout());
        assertTrue(subject.getPrincipals().isEmpty());
        assertTrue(subject.getPublicCredentials().isEmpty());
    }

    @Test
    void otherCredentialsAreLeftToOaksOwnModules() throws Exception {
        grant();
        Subject subject = new Subject();
        OboLoginModuleFactory.DelegationLoginModule module = module(subject, new SimpleCredentials(USER, new char[0]));
        assertFalse(module.login());
        assertFalse(module.commit());
        assertTrue(subject.getPrincipals().isEmpty());
    }

    @Test
    void unknownExpiredRevokedAndForeignConfigurationCredentialsAreRefused() throws Exception {
        String access = grant();
        assertThrows(LoginException.class, () -> module(new Subject(), new OboCredentials(access.replace('.', '-'))).login());
        String unknown = "goa_" + OboService.recordId(USER) + "." + OboService.random();
        assertThrows(LoginException.class, () -> module(new Subject(), new OboCredentials(unknown)).login());
        Node grant = admin.getNode(OboService.path(OboService.ROOT, OboService.id(access)));
        grant.setProperty("revoked", true);
        admin.save();
        assertThrows(LoginException.class, () -> module(new Subject(), new OboCredentials(access)).login());
        String expired = grant();
        admin.getNode(OboService.path(OboService.ROOT, OboService.id(expired))).setProperty("accessExpires", 1L);
        admin.save();
        assertThrows(LoginException.class, () -> module(new Subject(), new OboCredentials(expired)).login());
        String rotated = grant();
        when(config.clientSecretSha256()).thenReturn(OboService.hash("rotated"));
        service.activate(config);
        assertThrows(LoginException.class, () -> module(new Subject(), new OboCredentials(rotated)).login());
    }

    @Test
    void administratorsAreRefusedEvenWhenMembershipIsInAnOverflowListOrNested() throws Exception {
        String access = grant();
        UserManager users = ((JackrabbitSession) admin).getUserManager();
        Group administrators = (Group) users.getAuthorizable("administrators");
        for (int i = 0; i < 120; i++) administrators.addMember(users.createUser("zz-filler-" + i, null));
        Group nested = users.createGroup("zz-nested-admins");
        administrators.addMember(nested);
        nested.addMember(users.getAuthorizable(USER));
        admin.save();
        assertTrue(admin.nodeExists(administrators.getPath() + "/rep:membersList"));
        Subject subject = new Subject();
        assertThrows(LoginException.class, () -> module(subject, new OboCredentials(access)).login());
        assertTrue(subject.getPrincipals().isEmpty());

        when(config.allowAdministrators()).thenReturn(true);
        assertTrue(module(new Subject(), new OboCredentials(access)).login());
    }

    @Test
    void aDisabledOrRecreatedUserCannotUseTheGrant() throws Exception {
        String access = grant();
        UserManager users = ((JackrabbitSession) admin).getUserManager();
        ((org.apache.jackrabbit.api.security.user.User) users.getAuthorizable(USER)).disable("left the company");
        admin.save();
        assertThrows(LoginException.class, () -> module(new Subject(), new OboCredentials(access)).login());
        users.getAuthorizable(USER).remove();
        admin.save();
        users.createUser(USER, null);
        admin.save();
        assertThrows(LoginException.class, () -> module(new Subject(), new OboCredentials(access)).login());
    }

    @Test
    void administrativePrincipalTypesAreRecognised() {
        Principal admin = new org.apache.jackrabbit.oak.spi.security.principal.AdminPrincipal() {
            @Override public String getName() { return "admin"; }
        };
        Principal system = new org.apache.jackrabbit.oak.spi.security.principal.SystemUserPrincipal() {
            @Override public String getName() { return "some-service"; }
        };
        assertTrue(OboLoginModuleFactory.DelegationLoginModule.administrative(Set.of(admin)));
        assertTrue(OboLoginModuleFactory.DelegationLoginModule.administrative(Set.of(system)));
        assertTrue(OboLoginModuleFactory.DelegationLoginModule.administrative(Set.<Principal>of(() -> "administrators")));
        assertFalse(OboLoginModuleFactory.DelegationLoginModule.administrative(Set.<Principal>of(() -> "authors")));
    }
}
