package com.gradial.core.oauth.obo;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Collections;
import java.util.Deque;
import java.util.List;
import java.util.Locale;

/**
 * The fixed set of credential and administration endpoints a delegated session may never call. It is not
 * configurable. Everything else, including every content write, runs with the consenting user's own AEM
 * ACLs: delegation never grants more than that user has, and this list does not try to narrow content access.
 *
 * <p>Matched on the request path only (the normalized request URI, and in {@link OboAuthenticationFilter}
 * also the Sling resource the request resolved to). Request bodies and parameters are not inspected: three
 * review rounds showed that a guard which re-derives Sling POST targets from parameters cannot match
 * {@code SlingPostServlet}'s own resolution (suffixes, {@code @} names, multipart values, {@code :operation=import},
 * recursive deletes, other POST servlets), so that guard was removed.
 */
final class OboPaths {
    /**
     * Prefix, its descendants and its selector or extension forms; compared in lower case.
     *
     * <ul>
     * <li>{@code /bin/gradial/obo}: this bundle's own authorize, token and revoke endpoints
     * ({@link OboServlet}, {@code OboAuthenticationHandler.TOKEN_PATH}/{@code REVOKE_PATH}). A delegated token must
     * never mint, refresh, consent to or revoke delegation.</li>
     * <li>{@code /oauth}: Granite OAuth server endpoints ({@code com.adobe.granite.oauth.server}, for example
     * {@code /oauth/token} served by {@code OAuth2TokenEndpointServlet}). They mint AEM OAuth tokens.</li>
     * <li>{@code /libs/granite/oauth}: Granite OAuth consent and client management ({@code /libs/granite/oauth/authorize},
     * served by {@code OAuth2AuthorizationCodeIssuer}; {@code /libs/granite/oauth/content/clients.html} and
     * {@code newclient.html}). They issue codes and create OAuth clients with secrets.</li>
     * <li>{@code /crx/packmgr}: Package Manager. Installing a package writes code, OSGi configuration and ACLs, and
     * repoinit configurations it carries run as the repository administrator.</li>
     * <li>{@code /crx/de}: CRXDE Lite, a generic repository editor.</li>
     * <li>{@code /crx/server}: JCR remoting (WebDAV and DavEx). A second, non-Sling write protocol for any
     * repository operation, including access control changes.</li>
     * <li>{@code /libs/granite/security}: user, group, permission and keystore administration (for example
     * {@code /libs/granite/security/post/authorizables}). Three read-only identity endpoints are allowed, see
     * {@link #IDENTITY}.</li>
     * <li>{@code /system/console}: the Felix web console (bundles, OSGi configuration, JMX).</li>
     * </ul>
     */
    static final List<String> REFUSED = Collections.unmodifiableList(Arrays.asList(
            "/bin/gradial/obo", "/oauth", "/libs/granite/oauth", "/crx/packmgr", "/crx/de", "/crx/server",
            "/libs/granite/security", "/system/console"));

    /**
     * Read-only identity endpoints under {@code /libs/granite/security}, allowed for GET and HEAD only. Gradial reads
     * them to confirm whom a run acts as: gradial/v2 {@code packages/server/aem/src/query/aem-principal.ts:8} and
     * {@code instance-metadata.ts:289} (currentuser.json), {@code permissions.ts:179-181} (currentuser, whoami,
     * userinfo), {@code service-user-probe.ts:38} (currentuser.json?props=memberOf).
     */
    static final List<String> IDENTITY = Collections.unmodifiableList(Arrays.asList(
            "/libs/granite/security/currentuser", "/libs/granite/security/whoami", "/libs/granite/security/userinfo"));

    private OboPaths() { }

    /** True when a delegated request for this raw request URI must be refused (URI decoding applies). */
    static boolean refuses(String method, String rawUri) {
        String normalized = normalize(rawUri);
        return normalized == null || refusesPath(method, normalized);
    }

    /** True when a delegated request may not act on this already-normalized path. */
    static boolean refusesPath(String method, String path) {
        String lower = path.toLowerCase(Locale.ROOT);
        if ("GET".equalsIgnoreCase(method) || "HEAD".equalsIgnoreCase(method)) {
            for (String allowed : IDENTITY) if (covers(allowed, lower)) return false;
        }
        for (String prefix : REFUSED) if (covers(prefix, lower)) return true;
        return false;
    }

    /** A prefix covers itself, its descendants and its selector or extension forms. */
    private static boolean covers(String prefix, String path) {
        return path.equals(prefix) || path.startsWith(prefix + "/") || path.startsWith(prefix + ".");
    }

    /**
     * Reads a request path the way the servlet container does: drops the query and path parameters,
     * decodes percent escapes once, collapses repeated slashes and resolves dot segments. Returns null
     * for anything that cannot be read safely, which callers treat as refused.
     */
    static String normalize(String raw) {
        if (raw == null || raw.isEmpty() || raw.charAt(0) != '/') return null;
        int query = raw.indexOf('?');
        String path = (query >= 0 ? raw.substring(0, query) : raw).replaceAll(";[^/]*", "");
        String decoded = decode(path);
        if (decoded == null || decoded.indexOf('\\') >= 0 || decoded.indexOf('\0') >= 0) return null;
        Deque<String> segments = new ArrayDeque<>();
        for (String segment : decoded.split("/")) {
            if (segment.isEmpty() || ".".equals(segment)) continue;
            if ("..".equals(segment)) {
                if (segments.isEmpty()) return null;
                segments.removeLast();
            } else {
                segments.addLast(segment);
            }
        }
        return "/" + String.join("/", segments);
    }

    private static String decode(String value) {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '%') {
                if (i + 2 >= value.length()) return null;
                int high = Character.digit(value.charAt(i + 1), 16);
                int low = Character.digit(value.charAt(i + 2), 16);
                if (high < 0 || low < 0) return null;
                bytes.write(high * 16 + low);
                i += 2;
            } else if (c < 0x80) {
                bytes.write(c);
            } else {
                byte[] encoded = String.valueOf(c).getBytes(StandardCharsets.UTF_8);
                bytes.write(encoded, 0, encoded.length);
            }
        }
        return new String(bytes.toByteArray(), StandardCharsets.UTF_8);
    }
}
