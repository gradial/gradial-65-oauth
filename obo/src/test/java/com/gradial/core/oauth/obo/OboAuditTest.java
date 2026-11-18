package com.gradial.core.oauth.obo;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import uk.org.lidalia.slf4jtest.LoggingEvent;
import uk.org.lidalia.slf4jtest.TestLogger;
import uk.org.lidalia.slf4jtest.TestLoggerFactory;

class OboAuditTest {
    private final TestLogger audit = TestLoggerFactory.getTestLogger(OboAudit.LOGGER);

    @AfterEach
    void clear() { TestLoggerFactory.clearAll(); }

    @Test
    void securityEventsAreLoggedWithoutAnyCredential() throws Exception {
        OboFixture fixture = new OboFixture();
        String verifier = OboService.random();
        String nonce = fixture.service.consent(OboFixture.USER, OboFixture.CLIENT, OboFixture.REDIRECT, OboService.challenge(verifier), OboFixture.STATE);
        String code = fixture.service.authorize(nonce, OboFixture.USER, true).code;
        OboService.Tokens first = fixture.service.exchange(code, OboFixture.REDIRECT, verifier);
        OboService.Tokens second = fixture.service.refresh(first.refresh);
        assertThrows(Exception.class, () -> fixture.service.refresh(first.refresh));
        assertThrows(Exception.class, () -> fixture.service.exchange(code, OboFixture.REDIRECT, verifier));

        StringBuilder all = new StringBuilder();
        for (LoggingEvent event : audit.getAllLoggingEvents()) all.append(event.getMessage()).append('\n');
        String log = all.toString();
        assertTrue(log.contains("event=consent_approved user=" + OboFixture.USER));
        assertTrue(log.contains("event=grant_issued user=" + OboFixture.USER));
        assertTrue(log.contains("event=grant_revoked user=" + OboFixture.USER) && log.contains("reason=refresh_replay"));
        String id = OboFixture.idOf(first.access);
        for (String secret : new String[] {nonce, code, first.access, first.refresh, second.access, second.refresh, id,
                nonce.substring(nonce.indexOf('.') + 1), first.access.substring(first.access.indexOf('.') + 1)}) {
            assertFalse(log.contains(secret), "audit log must not contain credentials or record ids");
        }
        assertTrue(log.contains("grant=" + OboService.fingerprint(id)));
    }

    @Test
    void forgedLineBreaksInUserIdsCannotSplitAnEvent() {
        String line = OboAudit.line("consent_refused", "x\ngradial-obo event=grant_issued", null, "reason=a\rb");
        assertFalse(line.contains("\n"));
        assertFalse(line.contains("\r"));
    }
}
