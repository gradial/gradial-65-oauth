package com.gradial.core.oauth.obo;

import static org.junit.jupiter.api.Assertions.*;

import javax.jcr.Node;
import javax.jcr.RepositoryException;
import javax.jcr.Session;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Two real Oak sessions race one refresh rotation. Oak sessions hold their own snapshot and a conflicting save fails
 * for real, which the in-memory fixture cannot do. The losing request runs inside the winner's window: it has read the
 * grant and modified it, then another session commits the rotation before the loser's save is applied.
 */
class OboConcurrentRefreshOakTest {
    private OboFixture fixture;
    private OboService service;
    private final String verifier = OboService.random();

    @BeforeEach
    void setup() throws Exception {
        fixture = new OboFixture(true);
        service = fixture.service;
    }

    private OboService.Tokens tokens() throws RepositoryException {
        String nonce = service.consent(OboFixture.USER, OboFixture.CLIENT, OboFixture.REDIRECT,
                OboService.challenge(verifier), OboFixture.STATE);
        String code = service.authorize(nonce, OboFixture.USER, true).code;
        return service.exchange(code, OboFixture.REDIRECT, verifier);
    }

    private Node grant(Session session, OboService.Tokens tokens) throws RepositoryException {
        return session.getNode(OboService.path(OboService.ROOT, OboFixture.idOf(tokens.access)));
    }

    @Test
    void theLosingSessionDiscardsItsRotationAndNoCredentialOfTheRaceSurvives() throws Exception {
        OboService.Tokens first = tokens();
        OboService.Tokens[] winner = new OboService.Tokens[1];
        fixture.beforeNextSave = () -> {
            try { winner[0] = service.refresh(first.refresh); } catch (RepositoryException e) { throw new AssertionError(e); }
        };

        assertThrows(RepositoryException.class, () -> service.refresh(first.refresh), "the loser gets no tokens");
        assertNotNull(winner[0], "the winner's rotation was committed while the loser was mid-request");

        Session session = fixture.open();
        try {
            Node grant = grant(session, first);
            // The loser's own rotation (a second rotation, its own refresh hash) was discarded, not merged over the winner's.
            assertEquals(1, grant.getProperty("rotations").getLong(), "only the winner's rotation is persisted");
            assertEquals(OboService.hash(winner[0].refresh), grant.getProperty("refreshHash").getString(),
                    "the stored refresh credential is the winner's, not the loser's");
            assertEquals(1, grant.getProperty("usedRefreshHashes").getValues().length);
            assertEquals(OboService.hash(first.refresh), grant.getProperty("usedRefreshHashes").getValues()[0].getString());
            // The loser observed the winner's committed rotation, saw its credential consumed, and revoked the family.
            assertTrue(grant.hasProperty("revoked") && grant.getProperty("revoked").getBoolean(), "a consumed credential replayed in a race revokes the family");
        } finally { session.logout(); }

        assertThrows(RepositoryException.class, () -> fixture.authenticate(winner[0].access), "no access credential survives");
        assertThrows(RepositoryException.class, () -> service.refresh(winner[0].refresh), "no refresh credential survives");
        assertThrows(RepositoryException.class, () -> fixture.authenticate(first.access));
        assertThrows(RepositoryException.class, () -> service.refresh(first.refresh));
    }

    @Test
    void withoutARaceTheSameRotationSucceedsOnOak() throws Exception {
        OboService.Tokens first = tokens();
        OboService.Tokens second = service.refresh(first.refresh);
        assertEquals(OboFixture.USER, fixture.authenticate(second.access));
        assertThrows(RepositoryException.class, () -> fixture.authenticate(first.access));
        Session session = fixture.open();
        try {
            assertFalse(grant(session, first).hasProperty("revoked") && grant(session, first).getProperty("revoked").getBoolean());
        } finally { session.logout(); }
    }
}
