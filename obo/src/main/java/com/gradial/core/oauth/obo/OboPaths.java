package com.gradial.core.oauth.obo;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Deque;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Paths a delegated session may never call. Delegation carries the user's whole AEM authority, but
 * Gradial needs only content APIs, so administrative surfaces are refused even for users who could
 * use them in a browser. An entry {@code write:/path} refuses only methods other than GET and HEAD.
 */
final class OboPaths {
    static final String WRITE = "write:";
    /** Always refused; configuration cannot remove these. They mint or manage credentials. */
    static final List<String> BASELINE = Collections.unmodifiableList(Arrays.asList(
            "/bin/gradial/obo", "/oauth", "/libs/granite/oauth"));
    /** Default {@code deniedPaths}: package, console, CRX, security, operations and cloud-config surfaces. */
    static final String[] DEFAULTS = {
        "/crx", "/system", "/etc/packages", "/libs/granite/security", "/libs/cq/security",
        "/libs/granite/operations", "/libs/granite/backup", "/libs/granite/cluster", "/libs/granite/distribution",
        "/etc/cloudservices", WRITE + "/home", WRITE + "/etc/replication"
    };
    /** Read-only identity endpoints Gradial uses to confirm who it acts as. GET and HEAD only. */
    static final List<String> READABLE = Collections.unmodifiableList(Arrays.asList(
            "/libs/granite/security/currentuser", "/libs/granite/security/whoami",
            "/libs/granite/security/userinfo", "/libs/cq/security/userinfo"));

    private final List<String> denied;
    private final List<String> writeDenied;

    private OboPaths(List<String> denied, List<String> writeDenied) {
        this.denied = denied;
        this.writeDenied = writeDenied;
    }

    static OboPaths of(String[] configured) {
        Set<String> all = new LinkedHashSet<>(BASELINE);
        Set<String> writes = new LinkedHashSet<>();
        for (String entry : configured == null || configured.length == 0 ? DEFAULTS : configured) {
            if (entry == null) continue;
            String value = entry.trim();
            boolean write = value.toLowerCase(Locale.ROOT).startsWith(WRITE);
            String path = normalize(write ? value.substring(WRITE.length()).trim() : value);
            if (path == null || path.length() < 2) continue;
            (write ? writes : all).add(path.toLowerCase(Locale.ROOT));
        }
        return new OboPaths(Collections.unmodifiableList(new ArrayList<>(all)),
                Collections.unmodifiableList(new ArrayList<>(writes)));
    }

    List<String> denied() { return denied; }
    List<String> writeDenied() { return writeDenied; }

    /** True when a delegated request for this raw request URI must be refused (URI decoding applies). */
    boolean refuses(String method, String path) {
        String normalized = normalize(path);
        return normalized == null || refusesRepositoryPath(method, normalized);
    }

    /**
     * True when a delegated request may not act on this exact repository path. The path is compared as
     * given: no URI decoding, no query stripping, no dot-segment resolution. Callers pass only paths
     * already proven absolute and normalized.
     */
    boolean refusesRepositoryPath(String method, String path) {
        String lower = path.toLowerCase(Locale.ROOT);
        boolean read = "GET".equalsIgnoreCase(method) || "HEAD".equalsIgnoreCase(method);
        if (read) {
            for (String allowed : READABLE) if (covers(allowed, lower)) return false;
        }
        for (String prefix : denied) if (covers(prefix, lower)) return true;
        if (!read) {
            for (String prefix : writeDenied) if (covers(prefix, lower)) return true;
        }
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
