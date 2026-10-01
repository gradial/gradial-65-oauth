package com.gradial.core.oauth.obo;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.lang.reflect.Field;
import java.net.URI;
import java.util.Base64;
import java.util.Calendar;

import javax.jcr.Node;
import javax.jcr.Repository;
import javax.jcr.RepositoryException;
import javax.jcr.Session;

import org.apache.jackrabbit.api.JackrabbitSession;
import org.apache.jackrabbit.api.security.user.User;
import org.apache.jackrabbit.api.security.user.UserManager;
import org.apache.sling.jcr.api.SlingRepository;
import org.apache.sling.testing.mock.jcr.MockJcr;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.AdditionalAnswers;

class OboServiceTest {
    private static final String USER = "ordinary-author";
    private static final String CLIENT = "gradial";
    private static final String REDIRECT = "https://app.gradial.com/aem/callback";
    private static final String STATE = "0123456789abcdef0123456789abcdef";
    private final String verifier = OboService.random();
    private OboService service;
    private Repository storage;
    private User user;
    private UserManager users;
    private OboConfiguration config;

    @BeforeEach
    void setup() throws Exception {
        storage = MockJcr.newRepository();
        Session session = storage.login();
        Node node = session.getRootNode();
        for (String segment : OboService.ROOT.substring(1).split("/")) node = node.addNode(segment, "nt:unstructured");
        session.getRootNode().addNode("home", "nt:unstructured").addNode("users", "nt:unstructured")
                .addNode(USER, "nt:unstructured").setProperty("jcr:created", Calendar.getInstance());
        session.save();
        session.logout();
        user = mock(User.class);
        when(user.getPath()).thenReturn("/home/users/" + USER);
        users = mock(UserManager.class);
        when(users.getAuthorizable(USER)).thenReturn(user);
        SlingRepository repository = mock(SlingRepository.class);
        when(repository.loginService("obo", null)).thenAnswer(invocation -> {
            JackrabbitSession delegated = mock(JackrabbitSession.class, AdditionalAnswers.delegatesTo(storage.login()));
            doReturn(users).when(delegated).getUserManager();
            return delegated;
        });
        service = new OboService();
        Field field = OboService.class.getDeclaredField("repository");
        field.setAccessible(true);
        field.set(service, repository);
        config = mock(OboConfiguration.class);
        when(config.enabled()).thenReturn(true);
        when(config.clientId()).thenReturn(CLIENT);
        when(config.clientSecretSha256()).thenReturn(OboService.hash("a-long-random-client-secret"));
        when(config.publicOrigin()).thenReturn("https://author.example.com");
        when(config.redirectUris()).thenReturn(new String[] {REDIRECT});
        when(config.accessTokenSeconds()).thenReturn(300);
        when(config.grantSeconds()).thenReturn(86400);
        service.activate(config);
    }

    private String consent() throws RepositoryException {
        return service.consent(USER, CLIENT, REDIRECT, OboService.challenge(verifier), STATE);
    }
    private String code() throws RepositoryException {
        return service.authorize(consent(), USER, true).code;
    }
    private OboService.Tokens tokens() throws RepositoryException { return service.exchange(code(), REDIRECT, verifier); }

    @Test
    void originalUserIsAuthenticatedWithoutStoringRawCredentials() throws Exception {
        OboService.Tokens tokens = tokens();
        assertEquals(USER, service.authenticate(tokens.access));
        Session session = storage.login();
        try {
            Node grant = session.getNode(OboService.ROOT + "/" + tokens.access.substring(4, tokens.access.indexOf('.')));
            assertEquals(OboService.hash(tokens.access), grant.getProperty("accessHash").getString());
            assertEquals(OboService.hash(tokens.refresh), grant.getProperty("refreshHash").getString());
            assertFalse(grant.hasProperty("accessToken"));
            assertFalse(grant.hasProperty("password"));
        } finally { session.logout(); }
    }

    @Test
    void consentNonceIsBoundToTheSignedInUserAndCanOnlyBeApprovedOnce() throws Exception {
        String nonce = consent();
        assertThrows(RepositoryException.class, () -> service.authorize(nonce, "other-user", true));
        OboService.Authorization authorization = service.authorize(nonce, USER, true);
        assertEquals(REDIRECT, authorization.redirect);
        assertEquals(STATE, authorization.state);
        assertThrows(RepositoryException.class, () -> service.authorize(nonce, USER, true));
    }

    @Test
    void deniedConsentCannotBeExchanged() throws Exception {
        String nonce = consent();
        assertNull(service.authorize(nonce, USER, false).code);
        assertThrows(RepositoryException.class, () -> service.authorize(nonce, USER, true));
    }

    @Test
    void codeRequiresExactCallbackAndPkceAndIsSingleUse() throws Exception {
        String code = code();
        assertThrows(RepositoryException.class, () -> service.exchange(code, "https://attacker.example/callback", verifier));
        assertThrows(RepositoryException.class, () -> service.exchange(code, REDIRECT, OboService.random()));
        assertThrows(RepositoryException.class, () -> service.exchange(code, REDIRECT, "short"));
        assertEquals(USER, service.authenticate(service.exchange(code, REDIRECT, verifier).access));
        assertThrows(RepositoryException.class, () -> service.exchange(code, REDIRECT, verifier));
    }

    @Test
    void rotationInvalidatesOldAccessAndRefreshReplayRevokesTheFamily() throws Exception {
        OboService.Tokens first = tokens();
        OboService.Tokens second = service.refresh(first.refresh);
        assertEquals(USER, service.authenticate(second.access));
        assertThrows(RepositoryException.class, () -> service.authenticate(first.access));
        assertThrows(RepositoryException.class, () -> service.authenticate(second.refresh));
        assertThrows(RepositoryException.class, () -> service.refresh(first.refresh));
        assertThrows(RepositoryException.class, () -> service.authenticate(second.access));
        assertThrows(RepositoryException.class, () -> service.refresh(second.refresh));
    }

    @Test
    void unknownSecretDoesNotRevokeButEitherCurrentCredentialRevokesTheFamily() throws Exception {
        OboService.Tokens first = tokens();
        service.revoke(first.access.substring(0, first.access.indexOf('.') + 1) + OboService.random());
        assertEquals(USER, service.authenticate(first.access));
        service.revoke(first.access);
        assertThrows(RepositoryException.class, () -> service.authenticate(first.access));
        assertThrows(RepositoryException.class, () -> service.refresh(first.refresh));
        OboService.Tokens second = tokens();
        service.revoke(second.refresh);
        assertThrows(RepositoryException.class, () -> service.authenticate(second.access));
    }

    @Test
    void disablingOrDeletingTheUserStopsAccessAndRenewal() throws Exception {
        OboService.Tokens tokens = tokens();
        when(user.isDisabled()).thenReturn(true);
        assertThrows(RepositoryException.class, () -> service.authenticate(tokens.access));
        assertThrows(RepositoryException.class, () -> service.refresh(tokens.refresh));
        when(user.isDisabled()).thenReturn(false);
        when(users.getAuthorizable(USER)).thenReturn(null);
        assertThrows(RepositoryException.class, () -> service.authenticate(tokens.access));
        assertThrows(RepositoryException.class, () -> service.refresh(tokens.refresh));
    }

    @Test
    void aReplacementAccountWithTheSameUsernameCannotInheritTheOldGrant() throws Exception {
        OboService.Tokens tokens = tokens();
        Session session = storage.login();
        try {
            Node original = session.getNode("/home/users/" + USER);
            Calendar replacementCreated = original.getProperty("jcr:created").getDate();
            replacementCreated.setTimeInMillis(replacementCreated.getTimeInMillis() + 1);
            // Preserve the same path and UUID, as Oak does when a username is recreated.
            original.setProperty("jcr:created", replacementCreated);
            session.save();
        } finally { session.logout(); }
        assertThrows(RepositoryException.class, () -> service.authenticate(tokens.access));
        assertThrows(RepositoryException.class, () -> service.refresh(tokens.refresh));
    }

    @Test
    void systemUsersAndAnonymousCannotAuthorize() throws Exception {
        when(user.isSystemUser()).thenReturn(true);
        assertThrows(RepositoryException.class, this::consent);
        assertThrows(RepositoryException.class, () -> service.consent("anonymous", CLIENT, REDIRECT, OboService.challenge(verifier), STATE));
    }

    @Test
    void onlyRegisteredCallbacksAndClientAreAccepted() {
        assertThrows(RepositoryException.class, () -> service.consent(USER, CLIENT, REDIRECT + "/", OboService.challenge(verifier), STATE));
        assertThrows(RepositoryException.class, () -> service.consent(USER, "other-client", REDIRECT, OboService.challenge(verifier), STATE));
        assertThrows(RepositoryException.class, () -> service.consent(USER, CLIENT, REDIRECT, "short", STATE));
    }

    @Test
    void expiredGrantsCannotAuthenticateOrRefreshAndAreCleanedUp() throws Exception {
        OboService.Tokens tokens = tokens();
        Session session = storage.login();
        try {
            session.getNode(OboService.ROOT + "/" + tokens.access.substring(4, tokens.access.indexOf('.'))).setProperty("expires", 0L);
            session.save();
        } finally { session.logout(); }
        assertThrows(RepositoryException.class, () -> service.authenticate(tokens.access));
        assertThrows(RepositoryException.class, () -> service.refresh(tokens.refresh));
        service.run();
        Session verify = storage.login();
        try { assertFalse(verify.getNode(OboService.ROOT).hasNodes()); } finally { verify.logout(); }
    }

    @Test
    void changingClientConfigurationInvalidatesExistingGrants() throws Exception {
        OboService.Tokens tokens = tokens();
        when(config.clientSecretSha256()).thenReturn(OboService.hash("replacement-secret"));
        service.activate(config);
        assertThrows(RepositoryException.class, () -> service.authenticate(tokens.access));
        assertThrows(RepositoryException.class, () -> service.refresh(tokens.refresh));
    }

    @Test
    void clientAuthenticationRequiresTheConfiguredSecret() {
        assertTrue(service.clientMatches(CLIENT, "a-long-random-client-secret"));
        assertFalse(service.clientMatches("other", "a-long-random-client-secret"));
        assertFalse(service.clientMatches(CLIENT, "incorrect"));
        assertFalse(service.clientMatches(CLIENT, null));
    }

    @Test
    void insecureRemoteOriginsAndCallbacksAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> OboService.checkedUri("http://author.example.com"));
        assertThrows(IllegalArgumentException.class, () -> OboService.checkedUri("https://user@author.example.com"));
        assertThrows(IllegalArgumentException.class, () -> OboService.checkedUri("https://author.example.com/#fragment"));
        assertEquals(URI.create("http://localhost:14300/callback"), OboService.checkedUri("http://localhost:14300/callback"));
    }
}
