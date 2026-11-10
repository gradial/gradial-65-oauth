package com.gradial.core.oauth.obo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Security events on one named logger, so a deployment can route them to its own audit file with a
 * standard Sling log configuration. Lines carry the AEM user ID and a grant fingerprint, never a
 * credential or a record id that a credential embeds.
 *
 * <pre>gradial-obo event=grant_revoked user=jdoe grant=3f9a0c1b2d4e reason=refresh_replay</pre>
 */
final class OboAudit {
    static final String LOGGER = "com.gradial.core.oauth.obo.audit";
    private static final Logger LOG = LoggerFactory.getLogger(LOGGER);

    private OboAudit() { }

    static void event(String event, String user, String recordId, String detail) {
        if (LOG.isInfoEnabled()) LOG.info(line(event, user, recordId, detail));
    }

    /** Routine events (each refresh) stay at DEBUG so normal use adds no log volume. */
    static void debug(String event, String user, String recordId) {
        if (LOG.isDebugEnabled()) LOG.debug(line(event, user, recordId, null));
    }

    static String line(String event, String user, String recordId, String detail) {
        StringBuilder line = new StringBuilder("gradial-obo event=").append(event)
                .append(" user=").append(user == null ? "-" : clean(user))
                .append(" grant=").append(OboService.fingerprint(recordId));
        if (detail != null) line.append(' ').append(clean(detail));
        return line.toString();
    }

    /** Log lines stay one line: user IDs and paths cannot inject a forged second event. */
    private static String clean(String value) {
        StringBuilder out = new StringBuilder(Math.min(value.length(), 256));
        for (int i = 0; i < value.length() && out.length() < 256; i++) {
            char c = value.charAt(i);
            out.append(Character.isISOControl(c) ? '_' : c);
        }
        return out.toString();
    }
}
