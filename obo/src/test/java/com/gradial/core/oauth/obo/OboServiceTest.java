package com.gradial.core.oauth.obo;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.lang.reflect.Field;
import java.net.URI;
import java.util.Base64;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

import javax.jcr.Node;
import javax.jcr.Repository;
import javax.jcr.RepositoryException;
import javax.jcr.Session;

import org.apache.jackrabbit.api.JackrabbitSession;
import org.apache.jackrabbit.api.security.user.Group;
import org.apache.jackrabbit.api.security.user.User;
import org.apache.jackrabbit.api.security.user.UserManager;
import org.apache.sling.jcr.api.SlingRepository;
import org.apache.sling.testing.mock.jcr.MockJcr;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.AdditionalAnswers;

class OboServiceTest {
    private static final String USER = OboFixture.USER;
    private static final String CLIENT = OboFixture.CLIENT;
    private static final String REDIRECT = OboFixture.REDIRECT;
    private static final String STATE = OboFixture.STATE;
    private final String verifier = OboService.random();
    private OboFixture fixture;
    private OboService service;
    private Repository storage;
    private User user;
    private UserManager users;
    private OboConfiguration config;

    @BeforeEach
    void setup() throws Exception {
        fixture = new OboFixture();
        service = fixture.service;
        storage = fixture.storage;
        user = fixture.user;
        users = fixture.users;
        config = fixture.config;
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
        assertEquals(USER, fixture.authenticate(tokens.access));
        Session session = storage.login();
        try {
            Node grant = session.getNode(OboService.path(OboService.ROOT, OboFixture.idOf(tokens.access)));
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
        assertEquals(USER, fixture.authenticate(service.exchange(code, REDIRECT, verifier).access));
        assertThrows(RepositoryException.class, () -> service.exchange(code, REDIRECT, verifier));
    }

    @Test
    void rotationInvalidatesOldAccessAndRefreshReplayRevokesTheFamily() throws Exception {
        OboService.Tokens first = tokens();
        OboService.Tokens second = service.refresh(first.refresh);
        assertEquals(USER, fixture.authenticate(second.access));
        assertThrows(RepositoryException.class, () -> fixture.authenticate(first.access));
        assertThrows(RepositoryException.class, () -> fixture.authenticate(second.refresh));
        assertThrows(RepositoryException.class, () -> service.refresh(first.refresh));
        assertThrows(RepositoryException.class, () -> fixture.authenticate(second.access));
        assertThrows(RepositoryException.class, () -> service.refresh(second.refresh));
    }

    @Test
    void unknownSecretDoesNotRevokeButEitherCurrentCredentialRevokesTheFamily() throws Exception {
        OboService.Tokens first = tokens();
        service.revoke(first.access.substring(0, first.access.indexOf('.') + 1) + OboService.random());
        assertEquals(USER, fixture.authenticate(first.access));
        service.revoke(first.access);
        assertThrows(RepositoryException.class, () -> fixture.authenticate(first.access));
        assertThrows(RepositoryException.class, () -> service.refresh(first.refresh));
        OboService.Tokens second = tokens();
        service.revoke(second.refresh);
        assertThrows(RepositoryException.class, () -> fixture.authenticate(second.access));
    }

    @Test
    void disablingOrDeletingTheUserStopsAccessAndRenewal() throws Exception {
        OboService.Tokens tokens = tokens();
        when(user.isDisabled()).thenReturn(true);
        assertThrows(RepositoryException.class, () -> fixture.authenticate(tokens.access));
        assertThrows(RepositoryException.class, () -> service.refresh(tokens.refresh));
        when(user.isDisabled()).thenReturn(false);
        when(users.getAuthorizable(USER)).thenReturn(null);
        assertThrows(RepositoryException.class, () -> fixture.authenticate(tokens.access));
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
        assertThrows(RepositoryException.class, () -> fixture.authenticate(tokens.access));
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
            session.getNode(OboService.path(OboService.ROOT, OboFixture.idOf(tokens.access))).setProperty("expires", 0L);
            session.save();
        } finally { session.logout(); }
        assertThrows(RepositoryException.class, () -> fixture.authenticate(tokens.access));
        assertThrows(RepositoryException.class, () -> service.refresh(tokens.refresh));
        service.run();
        Session verify = storage.login();
        verify.logout();
        assertEquals(0, OboFixture.records(storage, OboService.ROOT, 2));
    }

    @Test
    void changingClientConfigurationInvalidatesExistingGrants() throws Exception {
        OboService.Tokens tokens = tokens();
        when(config.clientSecretSha256()).thenReturn(OboService.hash("replacement-secret"));
        service.activate(config, java.util.Collections.emptyMap());
        assertThrows(RepositoryException.class, () -> fixture.authenticate(tokens.access));
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

    @Test
    void pendingConsentsAreCappedPerUserAndTheOldestIsEvicted() throws Exception {
        List<String> nonces = new ArrayList<>();
        for (int i = 0; i < 12; i++) {
            nonces.add(consent());
            Thread.sleep(2);
        }
        assertEquals(OboService.MAX_PENDING_CONSENTS, OboFixture.records(storage, OboService.CONSENTS, 2));
        assertThrows(RepositoryException.class, () -> service.authorize(nonces.get(0), USER, true));
        assertNotNull(service.authorize(nonces.get(11), USER, true).code);
    }

    @Test
    void anAuthorizeFloodDoesNotGrowStoredStateBeyondTheCap() throws Exception {
        for (int i = 0; i < 300; i++) consent();
        assertEquals(OboService.MAX_PENDING_CONSENTS, OboFixture.records(storage, OboService.CONSENTS, 2));
        assertEquals(0, OboFixture.records(storage, OboService.ROOT, 2));
    }

    @Test
    void recordsLiveInTheirOwnersFolderUnderAHashedBucket() throws Exception {
        OboService.Tokens tokens = tokens();
        String id = OboFixture.idOf(tokens.access);
        assertTrue(id.startsWith(OboService.userKey(USER)), "every record id starts with its owner's key");
        Session session = storage.login();
        try {
            String bucket = OboService.ROOT + "/" + OboService.userKey(USER).substring(0, 2);
            String folder = bucket + "/" + OboService.userKey(USER);
            assertTrue(session.nodeExists(folder + "/" + id));
            assertEquals("oak:Unstructured", session.getNode(bucket).getPrimaryNodeType().getName());
            assertEquals("oak:Unstructured", session.getNode(folder).getPrimaryNodeType().getName());
            assertFalse(session.getNode(folder + "/" + id).hasNodes(), "a grant has no child nodes");
        } finally { session.logout(); }
    }

    @Test
    void cleanupRemovesMoreThanOneThousandExpiredRecordsInOnePass() throws Exception {
        OboService.Tokens live = tokens();
        Session session = storage.login();
        try {
            Node grants = session.getNode(OboService.ROOT);
            for (int i = 0; i < 1500; i++) {
                Node bucket = grants.hasNode("ab") ? grants.getNode("ab") : grants.addNode("ab", "oak:Unstructured");
                Node folder = bucket.hasNode("ab00000000000000") ? bucket.getNode("ab00000000000000")
                        : bucket.addNode("ab00000000000000", "oak:Unstructured");
                folder.addNode("expired" + i, "oak:Unstructured").setProperty("expires", 0L);
            }
            session.save();
        } finally { session.logout(); }
        service.run();
        assertEquals(1, OboFixture.records(storage, OboService.ROOT, 2));
        assertEquals(USER, fixture.authenticate(live.access));
    }

    @Test
    void cleanupDropsExpiredConsentsAndTheirEmptyUserFolders() throws Exception {
        consent();
        Session session = storage.login();
        try {
            Node folder = session.getNode(OboService.CONSENTS).getNodes().nextNode().getNodes().nextNode();
            folder.getNodes().nextNode().setProperty("expires", 0L);
            session.save();
        } finally { session.logout(); }
        service.run();
        assertEquals(0, OboFixture.records(storage, OboService.CONSENTS, 2));
        assertEquals(0, OboFixture.records(storage, OboService.CONSENTS, 1));
    }

    @Test
    void administratorsAreRefusedByDefaultAtConsentAndAtEveryLaterUse() throws Exception {
        OboService.Tokens tokens = tokens();
        when(user.isAdmin()).thenReturn(true);
        assertThrows(RepositoryException.class, this::consent);
        assertThrows(RepositoryException.class, () -> fixture.authenticate(tokens.access));
        assertThrows(RepositoryException.class, () -> service.refresh(tokens.refresh));
    }

    @Test
    void membersOfTheAdministratorsGroupAreRefusedButOtherGroupsAreNot() throws Exception {
        Group editors = mock(Group.class);
        when(editors.getID()).thenReturn("editors");
        when(user.memberOf()).thenAnswer(call -> List.of(editors).iterator());
        assertNotNull(consent());
        Group administrators = mock(Group.class);
        when(administrators.getID()).thenReturn("administrators");
        when(user.memberOf()).thenAnswer(call -> List.of(editors, administrators).iterator());
        assertThrows(RepositoryException.class, this::consent);
    }

    @Test
    void allowAdministratorsIsAnExplicitOptIn() throws Exception {
        when(user.isAdmin()).thenReturn(true);
        when(config.allowAdministrators()).thenReturn(true);
        assertEquals(USER, fixture.authenticate(tokens().access));
    }

    @Test
    void reusingAnAuthorizationCodeRevokesTheTokensItProduced() throws Exception {
        String code = code();
        OboService.Tokens issued = service.exchange(code, REDIRECT, verifier);
        assertEquals(USER, fixture.authenticate(issued.access));
        assertThrows(RepositoryException.class, () -> service.exchange(code, REDIRECT, verifier));
        assertThrows(RepositoryException.class, () -> fixture.authenticate(issued.access));
        assertThrows(RepositoryException.class, () -> service.refresh(issued.refresh));
    }

    @Test
    void aWrongVerifierDoesNotConsumeOrRevokeAnything() throws Exception {
        String code = code();
        assertThrows(RepositoryException.class, () -> service.exchange(code, REDIRECT, OboService.random()));
        assertEquals(USER, fixture.authenticate(service.exchange(code, REDIRECT, verifier).access));
    }

    @Test
    void eachTokenTypeIsAcceptedOnlyWhereItBelongs() throws Exception {
        OboService.Tokens tokens = tokens();
        String code = code();
        String nonce = consent();
        assertThrows(RepositoryException.class, () -> service.refresh(tokens.access));
        assertThrows(RepositoryException.class, () -> service.exchange(tokens.access, REDIRECT, verifier));
        assertThrows(RepositoryException.class, () -> service.exchange(tokens.refresh, REDIRECT, verifier));
        assertThrows(RepositoryException.class, () -> fixture.authenticate(tokens.refresh));
        assertThrows(RepositoryException.class, () -> fixture.authenticate(code));
        assertThrows(RepositoryException.class, () -> service.refresh(code));
        assertThrows(RepositoryException.class, () -> fixture.authenticate(nonce));
        assertThrows(RepositoryException.class, () -> service.exchange(nonce, REDIRECT, verifier));
        assertThrows(RepositoryException.class, () -> service.refresh("gor_" + tokens.access.substring(4)));
        assertThrows(RepositoryException.class, () -> fixture.authenticate("goa_" + tokens.refresh.substring(4)));
        // None of the misuse above damaged the legitimate credentials or the pending code.
        assertEquals(USER, fixture.authenticate(tokens.access));
        assertEquals(USER, fixture.authenticate(service.exchange(code, REDIRECT, verifier).access));
    }

    @Test
    void aConflictingConcurrentRefreshRevokesTheFamilyInsteadOfReturningTokens() throws Exception {
        OboService.Tokens first = tokens();
        fixture.conflictOnNextSave = () -> { };
        assertThrows(RepositoryException.class, () -> service.refresh(first.refresh));
        Session session = storage.login();
        try {
            assertTrue(session.getNode(OboService.path(OboService.ROOT, OboFixture.idOf(first.refresh))).getProperty("revoked").getBoolean());
        } finally { session.logout(); }
        assertThrows(RepositoryException.class, () -> service.refresh(first.refresh));
    }
    @Test
    void refreshHistoryIsBoundedAndAGrantNeverGrowsChildNodes() throws Exception {
        OboService.Tokens current = tokens();
        List<String> consumed = new ArrayList<>();
        for (int i = 0; i < 40; i++) {
            consumed.add(current.refresh);
            current = service.refresh(current.refresh);
        }
        Session session = storage.login();
        try {
            Node grant = session.getNode(OboService.path(OboService.ROOT, OboFixture.idOf(current.access)));
            assertEquals(OboService.REFRESH_HISTORY, grant.getProperty("usedRefreshHashes").getValues().length);
            assertFalse(grant.hasNodes());
        } finally { session.logout(); }
        // An old credential outside the history is refused without revoking; a recent replay revokes the family.
        assertThrows(RepositoryException.class, () -> service.refresh(consumed.get(0)));
        assertEquals(USER, fixture.authenticate(current.access));
        assertThrows(RepositoryException.class, () -> service.refresh(consumed.get(consumed.size() - 1)));
        String latest = current.access;
        assertThrows(RepositoryException.class, () -> fixture.authenticate(latest));
    }

    @Test
    void callbackOriginAndLifetimeChangesKeepGrantsAndLoweringTheLifetimeShortensThem() throws Exception {
        OboService.Tokens tokens = tokens();
        when(config.redirectUris()).thenReturn(new String[] {"https://app.gradial.com/aem/other-callback"});
        when(config.publicOrigin()).thenReturn("https://author-2.example.com");
        when(config.accessTokenSeconds()).thenReturn(600);
        service.activate(config, java.util.Collections.emptyMap());
        assertEquals(USER, fixture.authenticate(tokens.access));
        OboService.Tokens renewed = service.refresh(tokens.refresh);
        Session session = storage.login();
        try {
            Node grant = session.getNode(OboService.path(OboService.ROOT, OboFixture.idOf(renewed.access)));
            grant.setProperty("created", OboService.now() - 120_000L);
            session.save();
        } finally { session.logout(); }
        when(config.grantSeconds()).thenReturn(60);
        when(config.accessTokenSeconds()).thenReturn(30);
        service.activate(config, java.util.Collections.emptyMap());
        assertThrows(RepositoryException.class, () -> fixture.authenticate(renewed.access));
        assertThrows(RepositoryException.class, () -> service.refresh(renewed.refresh));
    }

    @Test
    void liveGrantsPerUserAreCappedAndTheOldestIsEvicted() throws Exception {
        List<OboService.Tokens> issued = new ArrayList<>();
        for (int i = 0; i < OboService.MAX_GRANTS_PER_USER + 3; i++) {
            issued.add(tokens());
            Thread.sleep(2);
        }
        assertEquals(OboService.MAX_GRANTS_PER_USER, OboFixture.records(storage, OboService.ROOT, 2));
        assertThrows(RepositoryException.class, () -> fixture.authenticate(issued.get(0).access));
        assertEquals(USER, fixture.authenticate(issued.get(issued.size() - 1).access));
    }

    @Test
    void cleanupRemovesRevokedGrantsAndPreReleaseRecordsInBuckets() throws Exception {
        OboService.Tokens revoked = tokens();
        service.revoke(revoked.access);
        OboService.Tokens live = tokens();
        Session session = storage.login();
        try {
            Node bucket = session.getNode(OboService.ROOT).addNode("cd", "oak:Unstructured");
            Node legacy = bucket.addNode("pre-release-grant", "oak:Unstructured");
            legacy.setProperty("configurationHash", "old");
            legacy.addNode("used", "oak:Unstructured").addNode("x", "oak:Unstructured");
            session.save();
        } finally { session.logout(); }
        service.run();
        assertEquals(1, OboFixture.records(storage, OboService.ROOT, 2));
        assertEquals(USER, fixture.authenticate(live.access));
    }

    @Test
    void aTokenWhoseRecordIdNamesAnotherUserIsRefused() throws Exception {
        OboService.Tokens tokens = tokens();
        String forged = "goa_" + OboService.userKey("someone-else") + tokens.access.substring(20);
        assertThrows(RepositoryException.class, () -> fixture.authenticate(forged));
    }

    @Test
    void aLeftoverDeniedPathsValueIsIgnoredWithOneWarning() throws Exception {
        uk.org.lidalia.slf4jtest.TestLogger log = uk.org.lidalia.slf4jtest.TestLoggerFactory.getTestLogger(OboService.class);
        log.clear();
        java.util.Map<String, Object> leftover = new java.util.HashMap<>();
        leftover.put(OboService.REMOVED_DENIED_PATHS, new String[] {"/content/private"});
        service.activate(config, leftover);
        assertEquals(1, log.getLoggingEvents().stream().filter(e -> e.getLevel() == uk.org.lidalia.slf4jext.Level.WARN
                && e.getMessage().contains("deniedPaths")).count());
        log.clear();
        service.activate(config, java.util.Collections.emptyMap());
        assertTrue(log.getLoggingEvents().stream().noneMatch(e -> e.getMessage().contains("deniedPaths")));
    }
}
