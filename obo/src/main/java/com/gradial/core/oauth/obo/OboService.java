package com.gradial.core.oauth.obo;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

import javax.jcr.Node;
import javax.jcr.NodeIterator;
import javax.jcr.InvalidItemStateException;
import javax.jcr.ItemExistsException;
import javax.jcr.RepositoryException;
import javax.jcr.Session;

import org.apache.jackrabbit.api.JackrabbitSession;
import org.apache.jackrabbit.api.security.user.Authorizable;
import org.apache.jackrabbit.api.security.user.Group;
import org.apache.jackrabbit.api.security.user.User;
import org.apache.sling.jcr.api.SlingRepository;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.ConfigurationPolicy;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.metatype.annotations.Designate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component(service = {OboService.class, Runnable.class}, configurationPolicy = ConfigurationPolicy.REQUIRE,
        property = {"scheduler.period:Long=600", "scheduler.concurrent:Boolean=false", "scheduler.runOn=LEADER"})
@Designate(ocd = OboConfiguration.class)
public class OboService implements Runnable {
    static final String ROOT = "/var/gradial/obo/grants";
    static final String CONSENTS = "/var/gradial/obo/consents";
    /** Non-orderable, so large child sets stay cheap. Never use nt:unstructured for unbounded children. */
    static final String CONTAINER = "oak:Unstructured";
    static final int MAX_PENDING_CONSENTS = 5;
    private static final String ADMINISTRATORS = "administrators";
    private static final long CLEANUP_BUDGET_MS = 60_000;
    private static final int BUCKETS = 256;
    static final String SCHEME = "GradialOBO";
    private static final Pattern TOKEN = Pattern.compile("go[acnr]_[A-Za-z0-9_-]{43}\\.[A-Za-z0-9_-]{43}");
    private static final Pattern VERIFIER = Pattern.compile("[A-Za-z0-9._~-]{43,128}");
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Logger LOG = LoggerFactory.getLogger(OboService.class);
    @Reference
    private SlingRepository repository;
    private OboConfiguration config;
    private Set<String> redirects;
    private String configurationHash;
    private int cleanupCursor;

    @Activate
    protected void activate(OboConfiguration config) {
        if (!config.enabled()) {
            this.config = config;
            redirects = Collections.emptySet();
            configurationHash = "disabled";
            return;
        }
        if (config.enabled()) {
            if (config.clientId().isEmpty() || !config.clientSecretSha256().matches("[a-f0-9]{64}")
                    || config.redirectUris().length == 0 || config.accessTokenSeconds() < 30
                    || config.accessTokenSeconds() > 3600 || config.grantSeconds() < config.accessTokenSeconds()
                    || config.grantSeconds() > 2592000) {
                throw new IllegalArgumentException("Invalid user-delegation configuration");
            }
            URI origin = checkedUri(config.publicOrigin());
            if (origin.getRawQuery() != null || origin.getRawFragment() != null
                    || (origin.getRawPath() != null && !origin.getRawPath().isEmpty())) {
                throw new IllegalArgumentException("publicOrigin must be an origin without a path");
            }
            for (String redirect : config.redirectUris()) {
                checkedUri(redirect);
            }
        }
        this.config = config;
        redirects = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(config.redirectUris())));
        configurationHash = hash(config.clientId() + "\n" + config.clientSecretSha256() + "\n"
                + config.publicOrigin() + "\n" + String.join("\n", config.redirectUris()) + "\n"
                + config.accessTokenSeconds() + "\n" + config.grantSeconds());
    }

    static URI checkedUri(String value) {
        URI uri = URI.create(value);
        String host = uri.getHost();
        boolean loopback = "localhost".equals(host) || "127.0.0.1".equals(host) || "[::1]".equals(host);
        if (host == null || uri.getRawUserInfo() != null || uri.getRawFragment() != null
                || !("https".equals(uri.getScheme()) || ("http".equals(uri.getScheme()) && loopback))) {
            throw new IllegalArgumentException("HTTPS callback/origin required (localhost is allowed for development)");
        }
        return uri;
    }

    boolean enabled() { return config.enabled(); }
    boolean allowAdministrators() { return config.allowAdministrators(); }
    String origin() { return config.publicOrigin(); }

    boolean clientMatches(String client, String secret) {
        return enabled() && config.clientId().equals(client) && secret != null && secret.length() <= 512
                && equal(config.clientSecretSha256(), hash(secret));
    }

    String consent(String userId, String client, String redirect, String challenge, String state)
            throws RepositoryException {
        if (!enabled() || !config.clientId().equals(client) || !redirects.contains(redirect)
                || challenge == null || !challenge.matches("[A-Za-z0-9_-]{43}")
                || state == null || state.length() < 16 || state.length() > 512) {
            throw invalid();
        }
        return retrying(session -> {
            requireUser(session, userId);
            String nonce = token("gon", random());
            Node folder = child(child(session.getNode(CONSENTS), bucket(userId)), hash(userId));
            makeRoom(folder);
            Node consent = folder.addNode(id(nonce), CONTAINER);
            consent.setProperty("userId", userId);
            consent.setProperty("userIdentifier", userIdentifier(session, userId));
            consent.setProperty("configurationHash", configurationHash);
            consent.setProperty("redirect", redirect);
            consent.setProperty("challenge", challenge);
            consent.setProperty("state", state);
            consent.setProperty("consentHash", hash(nonce));
            consent.setProperty("created", now());
            consent.setProperty("expires", now() + 300000);
            session.save();
            return nonce;
        });
    }

    /** Keeps at most MAX_PENDING_CONSENTS - 1 live consents so the new one makes MAX; the oldest go first. */
    private static void makeRoom(Node folder) throws RepositoryException {
        List<Node> live = new ArrayList<>();
        NodeIterator nodes = folder.getNodes();
        while (nodes.hasNext()) {
            Node node = nodes.nextNode();
            if (expired(node)) node.remove(); else live.add(node);
        }
        live.sort(Comparator.comparingLong(OboService::created));
        for (int i = 0; live.size() - i >= MAX_PENDING_CONSENTS; i++) live.get(i).remove();
    }

    Authorization authorize(String nonce, String userId, boolean approved) throws RepositoryException {
        return retrying(session -> {
            requireToken(nonce, "gon");
            // Consents live under the signed-in user's own folder, so another user's nonce is simply not found.
            String path = CONSENTS + "/" + bucket(userId) + "/" + hash(userId) + "/" + id(nonce);
            Node consent = live(session, path);
            if (!userId.equals(string(consent, "userId")) || !matches(consent, "consentHash", nonce)) throw invalid();
            requireGrantUser(session, consent);
            String redirect = string(consent, "redirect");
            String state = string(consent, "state");
            String code = null;
            if (approved) {
                code = token("goc", id(nonce));
                Node grant = child(session.getNode(ROOT), bucket(id(nonce))).addNode(id(nonce), CONTAINER);
                grant.setProperty("userId", userId);
                grant.setProperty("userIdentifier", string(consent, "userIdentifier"));
                grant.setProperty("configurationHash", configurationHash);
                grant.setProperty("redirect", redirect);
                grant.setProperty("challenge", string(consent, "challenge"));
                grant.setProperty("codeHash", hash(code));
                grant.setProperty("expires", now() + 60000);
                grant.setProperty("revision", random());
            }
            consent.remove();
            session.save();
            return new Authorization(redirect, state, code);
        });
    }

    Tokens exchange(String code, String redirect, String verifier) throws RepositoryException {
        if (verifier == null || !VERIFIER.matcher(verifier).matches()) throw invalid();
        Session session = session();
        try {
            Node grant = grant(session, code, "goc");
            if (!matches(grant, "codeHash", code)) {
                // RFC 6749 4.1.2: a replayed code revokes what it already produced.
                if (matches(grant, "usedCodeHash", code)) {
                    grant.setProperty("revoked", true);
                    grant.setProperty("revision", random());
                    session.save();
                }
                throw invalid();
            }
            if (!string(grant, "redirect").equals(redirect)
                    || !equal(string(grant, "challenge"), challenge(verifier))) throw invalid();
            requireGrantUser(session, grant);
            grant.setProperty("usedCodeHash", hash(code));
            grant.setProperty("codeHash", "");
            grant.setProperty("expires", now() + config.grantSeconds() * 1000L);
            Tokens tokens = rotate(grant);
            session.save();
            return tokens;
        } finally { session.logout(); }
    }

    Tokens refresh(String refresh) throws RepositoryException {
        Session session = session();
        try {
            Node grant = grant(session, refresh, "gor");
            if (!matches(grant, "refreshHash", refresh)) {
                if (grant.hasNode("used/" + hash(refresh))) {
                    grant.setProperty("revoked", true);
                    grant.setProperty("revision", random());
                    session.save();
                }
                throw invalid();
            }
            requireGrantUser(session, grant);
            Node used = grant.hasNode("used") ? grant.getNode("used") : grant.addNode("used", CONTAINER);
            long rotations = grant.hasProperty("rotations") ? grant.getProperty("rotations").getLong() : 0;
            if (rotations >= 10000) throw invalid();
            grant.setProperty("rotations", rotations + 1);
            used.addNode(hash(refresh), CONTAINER);
            Tokens tokens = rotate(grant);
            session.save();
            return tokens;
        } catch (InvalidItemStateException e) {
            // A concurrent rotation must not let a consumed refresh credential remain reusable.
            session.refresh(false);
            Node grant = grant(session, refresh, "gor");
            if (grant.hasNode("used/" + hash(refresh))) {
                grant.setProperty("revoked", true);
                grant.setProperty("revision", random());
                session.save();
            }
            throw invalid();
        } finally { session.logout(); }
    }

    public String authenticate(String access) throws RepositoryException {
        Session session = session();
        try {
            Node grant = grant(session, access, "goa");
            if (!matches(grant, "accessHash", access) || grant.getProperty("accessExpires").getLong() <= now()) throw invalid();
            String userId = string(grant, "userId");
            requireGrantUser(session, grant);
            return userId;
        } finally { session.logout(); }
    }

    void revoke(String token) throws RepositoryException {
        if (token == null || !TOKEN.matcher(token).matches()) return;
        Session session = session();
        try {
            String path = grantPath(id(token));
            if (!session.nodeExists(path)) return;
            Node grant = session.getNode(path);
            if (!configurationHash.equals(string(grant, "configurationHash"))) return;
            if (matches(grant, "accessHash", token) || matches(grant, "refreshHash", token)
                    || grant.hasNode("used/" + hash(token))) {
                grant.setProperty("revoked", true);
                grant.setProperty("revision", random());
                session.save();
            }
        } finally { session.logout(); }
    }

    private Tokens rotate(Node grant) throws RepositoryException {
        String access = token("goa", grant.getName());
        String refresh = token("gor", grant.getName());
        grant.setProperty("accessHash", hash(access));
        grant.setProperty("refreshHash", hash(refresh));
        long accessExpires = Math.min(now() + config.accessTokenSeconds() * 1000L,
                grant.getProperty("expires").getLong());
        grant.setProperty("accessExpires", accessExpires);
        grant.setProperty("revision", random());
        return new Tokens(access, refresh, (int) Math.max(0, (accessExpires - now()) / 1000));
    }

    private Node grant(Session session, String token, String prefix) throws RepositoryException {
        requireToken(token, prefix);
        Node grant = live(session, grantPath(id(token)));
        if (grant.hasProperty("revoked") && grant.getProperty("revoked").getBoolean()) throw invalid();
        return grant;
    }

    /** A stored record that belongs to this configuration and has not expired. */
    private Node live(Session session, String path) throws RepositoryException {
        if (!enabled() || !session.nodeExists(path)) throw invalid();
        Node node = session.getNode(path);
        if (!configurationHash.equals(string(node, "configurationHash")) || expired(node)) throw invalid();
        return node;
    }

    private static void requireToken(String token, String prefix) throws RepositoryException {
        if (token == null || !TOKEN.matcher(token).matches() || !token.startsWith(prefix + "_")) throw invalid();
    }

    private static boolean expired(Node node) throws RepositoryException {
        return node.hasProperty("expires") && node.getProperty("expires").getLong() <= now();
    }

    private static long created(Node node) {
        try { return node.hasProperty("created") ? node.getProperty("created").getLong() : 0; }
        catch (RepositoryException e) { return 0; }
    }

    private static Node child(Node parent, String name) throws RepositoryException {
        return parent.hasNode(name) ? parent.getNode(name) : parent.addNode(name, CONTAINER);
    }

    /** Hashed bucket so no single parent holds every record. */
    static String bucket(String key) { return hash(key).substring(0, 2); }
    static String grantPath(String id) { return ROOT + "/" + bucket(id) + "/" + id; }

    private interface Operation<T> { T run(Session session) throws RepositoryException; }

    /** Retries when a concurrent writer (a sibling request or the cleanup job) created or removed a shared bucket. */
    private <T> T retrying(Operation<T> operation) throws RepositoryException {
        for (int attempt = 1; ; attempt++) {
            Session session = session();
            try {
                return operation.run(session);
            } catch (InvalidItemStateException | ItemExistsException e) {
                if (attempt >= 3) throw e;
            } finally { session.logout(); }
        }
    }

    void requireUser(Session session, String userId) throws RepositoryException {
        if (!(session instanceof JackrabbitSession) || userId == null || "anonymous".equals(userId)
                || userId.startsWith("oauth-")) throw invalid();
        Authorizable authorizable = ((JackrabbitSession) session).getUserManager().getAuthorizable(userId);
        if (!(authorizable instanceof User) || ((User) authorizable).isSystemUser() || ((User) authorizable).isDisabled()) throw invalid();
        // Delegation maps to the user's own principals, and for administrators that bypasses every ACL.
        if (!allowAdministrators() && administrator((User) authorizable)) throw invalid();
    }

    private static boolean administrator(User user) throws RepositoryException {
        if (user.isAdmin()) return true;
        Iterator<Group> groups = user.memberOf();
        while (groups != null && groups.hasNext()) {
            if (ADMINISTRATORS.equals(groups.next().getID())) return true;
        }
        return false;
    }

    private String userIdentifier(Session session, String userId) throws RepositoryException {
        requireUser(session, userId);
        Authorizable user = ((JackrabbitSession) session).getUserManager().getAuthorizable(userId);
        if (user == null) throw invalid();
        Node node = session.getNode(user.getPath());
        // Oak derives the UUID from the username; the protected creation date distinguishes replacements.
        return node.getIdentifier() + ":" + node.getProperty("jcr:created").getDate().getTimeInMillis();
    }

    private void requireGrantUser(Session session, Node grant) throws RepositoryException {
        // Recreating the same username must never inherit a previous person's delegation.
        if (!string(grant, "userIdentifier").equals(userIdentifier(session, string(grant, "userId")))) throw invalid();
    }

    private Session session() throws RepositoryException { return repository.loginService("obo", null); }
    static long now() { return System.currentTimeMillis(); }
    private static String id(String token) { return token.substring(4, token.indexOf('.')); }
    private static String token(String prefix, String id) { return prefix + "_" + id + "." + random(); }
    static String random() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
    static String challenge(String verifier) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest(verifier));
    }
    static String hash(String value) {
        StringBuilder hex = new StringBuilder(64);
        for (byte b : digest(value)) hex.append(String.format("%02x", b & 255));
        return hex.toString();
    }
    private static byte[] digest(String value) {
        try { return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)); }
        catch (NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }
    static boolean equal(String expected, String actual) {
        return MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8), actual.getBytes(StandardCharsets.UTF_8));
    }
    private static boolean matches(Node node, String property, String token) throws RepositoryException {
        return node.hasProperty(property) && equal(string(node, property), hash(token));
    }
    private static String string(Node node, String property) throws RepositoryException { return node.getProperty(property).getString(); }
    static InvalidDelegationException invalid() { return new InvalidDelegationException(); }
    static final class InvalidDelegationException extends RepositoryException {
        private static final long serialVersionUID = 1L;
        InvalidDelegationException() { super("Invalid or expired delegation"); }
    }

    @Override
    public void run() {
        if (!enabled()) return;
        long deadline = now() + CLEANUP_BUDGET_MS;
        try {
            Session session = session();
            try {
                Node grants = session.getNode(ROOT);
                Node consents = session.getNode(CONSENTS);
                int start = cleanupCursor;
                int next = 0;
                int pendingRemovals = 0;
                // No count cap: every bucket is swept. Only a time budget stops a pass, and the next one resumes there.
                for (int i = 0; i < BUCKETS; i++) {
                    int index = (start + i) % BUCKETS;
                    if (i > 0 && now() > deadline) { next = index; break; }
                    String name = String.format("%02x", index);
                    if (grants.hasNode(name)) pendingRemovals += sweep(grants.getNode(name), false);
                    if (consents.hasNode(name)) pendingRemovals += sweep(consents.getNode(name), true);
                    if (pendingRemovals >= 200) { session.save(); pendingRemovals = 0; }
                }
                session.save();
                cleanupCursor = next;
            } finally { session.logout(); }
        } catch (RepositoryException e) { LOG.warn("User-delegation cleanup failed ({})", e.getClass().getSimpleName()); }
    }

    private static int sweep(Node bucket, boolean perUser) throws RepositoryException {
        int removed = 0;
        NodeIterator nodes = bucket.getNodes();
        while (nodes.hasNext()) {
            Node node = nodes.nextNode();
            if (perUser) {
                removed += sweep(node, false);
                if (!node.hasNodes()) { node.remove(); removed++; }
            } else if (expired(node)) { node.remove(); removed++; }
        }
        return removed;
    }

    static final class Authorization {
        final String redirect;
        final String state;
        final String code;
        Authorization(String redirect, String state, String code) {
            this.redirect = redirect; this.state = state; this.code = code;
        }
    }
    static final class Tokens {
        final String access;
        final String refresh;
        final int expiresIn;
        Tokens(String access, String refresh, int expiresIn) {
            this.access = access; this.refresh = refresh; this.expiresIn = expiresIn;
        }
    }
}
