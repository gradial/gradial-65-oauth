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

import javax.jcr.InvalidItemStateException;
import javax.jcr.ItemExistsException;
import javax.jcr.Node;
import javax.jcr.NodeIterator;
import javax.jcr.RepositoryException;
import javax.jcr.Session;

import org.apache.jackrabbit.api.JackrabbitSession;
import org.apache.jackrabbit.api.security.user.Authorizable;
import org.apache.jackrabbit.api.security.user.Group;
import org.apache.jackrabbit.api.security.user.User;
import org.apache.jackrabbit.api.security.user.UserManager;
import org.apache.sling.jcr.api.SlingRepository;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.ConfigurationPolicy;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.metatype.annotations.Designate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Authorization-code server and grant store for user-scoped delegation.
 *
 * <p>Store layout: {@code <root>/<2 hex>/<16 hex user key>/<record id>}. Every record id starts with the
 * owner's user key, so a token locates its record directly and each user's records share one small
 * folder, which bounds them per user. Parents are non-orderable.
 */
@Component(service = {OboService.class, Runnable.class}, configurationPolicy = ConfigurationPolicy.REQUIRE,
        property = {"scheduler.period:Long=600", "scheduler.concurrent:Boolean=false", "scheduler.runOn=LEADER"})
@Designate(ocd = OboConfiguration.class)
public class OboService implements Runnable {
    static final String STORE = "/var/gradial/obo";
    static final String ROOT = STORE + "/grants";
    static final String CONSENTS = STORE + "/consents";
    /** Non-orderable, so child sets stay cheap. Never use nt:unstructured for record parents. */
    static final String CONTAINER = "oak:Unstructured";
    static final int MAX_PENDING_CONSENTS = 5;
    static final int MAX_GRANTS_PER_USER = 10;
    /** Consumed refresh credentials remembered per grant for replay detection, newest last. */
    static final int REFRESH_HISTORY = 16;
    static final int MAX_ROTATIONS = 10000;
    private static final String ADMINISTRATORS = "administrators";
    private static final long CLEANUP_BUDGET_MS = 60_000;
    private static final int SAVE_BATCH = 200;
    private static final int BUCKETS = 256;
    static final String SCHEME = "GradialOBO";
    private static final Pattern TOKEN = Pattern.compile("go[acnr]_[0-9a-f]{16}[A-Za-z0-9_-]{27}\\.[A-Za-z0-9_-]{43}");
    private static final Pattern VERIFIER = Pattern.compile("[A-Za-z0-9._~-]{43,128}");
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Logger LOG = LoggerFactory.getLogger(OboService.class);

    @Reference
    private SlingRepository repository;
    private OboConfiguration config;
    private Set<String> redirects;
    private String configurationHash;
    private OboPaths paths;
    private int cleanupCursor;

    @Activate
    protected void activate(OboConfiguration config) {
        this.config = config;
        if (!config.enabled()) {
            redirects = Collections.emptySet();
            configurationHash = "disabled";
            paths = OboPaths.of(config.deniedPaths());
            return;
        }
        require(!config.clientId().isEmpty(), "clientId is required");
        require(config.clientSecretSha256().matches("[a-f0-9]{64}"), "clientSecretSha256 must be 64 lowercase hex characters");
        require(config.redirectUris().length > 0, "redirectUris must list at least one callback");
        require(config.accessTokenSeconds() >= 30 && config.accessTokenSeconds() <= 3600, "accessTokenSeconds must be 30-3600");
        require(config.grantSeconds() >= config.accessTokenSeconds() && config.grantSeconds() <= 2592000,
                "grantSeconds must be between accessTokenSeconds and 2592000");
        URI origin = checkedUri(config.publicOrigin());
        require(origin.getRawQuery() == null && origin.getRawFragment() == null
                && (origin.getRawPath() == null || origin.getRawPath().isEmpty()), "publicOrigin must be an origin without a path");
        for (String redirect : config.redirectUris()) checkedUri(redirect);
        redirects = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(config.redirectUris())));
        paths = OboPaths.of(config.deniedPaths());
        // Only the client identity binds grants. Callbacks, origin and lifetimes can change without revoking
        // everyone; rotating the client secret deliberately ends every grant.
        configurationHash = hash(config.clientId() + "\n" + config.clientSecretSha256());
        OboAudit.event("service_enabled", null, null, "client=" + config.clientId());
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new IllegalArgumentException("Invalid user-delegation configuration: " + message);
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
    OboPaths paths() { return paths; }

    /** True when the authorize request names this deployment's client; only then may errors go to its callback. */
    boolean knownClient(String client) { return enabled() && client != null && config.clientId().equals(client); }

    /** True when the callback is registered exactly; only then may errors be redirected to it. */
    boolean registeredRedirect(String redirect) { return enabled() && redirect != null && redirects.contains(redirect); }

    boolean clientMatches(String client, String secret) {
        return enabled() && config.clientId().equals(client) && secret != null && secret.length() <= 512
                && equal(config.clientSecretSha256(), hash(secret));
    }

    String consent(String userId, String client, String redirect, String challenge, String state)
            throws RepositoryException {
        if (!knownClient(client)) throw invalid(Refusal.UNKNOWN_CLIENT);
        if (!registeredRedirect(redirect)) throw invalid(Refusal.UNREGISTERED_REDIRECT);
        if (challenge == null || !challenge.matches("[A-Za-z0-9_-]{43}")) throw invalid(Refusal.PKCE);
        if (state == null || state.length() < 16 || state.length() > 512) throw invalid(Refusal.STATE);
        return retrying(session -> {
            requireUser(session, userId);
            String id = recordId(userId);
            String nonce = token("gon", id);
            Node folder = folder(session, CONSENTS, id);
            prune(folder, MAX_PENDING_CONSENTS, null);
            Node consent = folder.addNode(id, CONTAINER);
            consent.setProperty("userId", userId);
            consent.setProperty("userIdentifier", userIdentifier(records(session), users(session), userId));
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

    Authorization authorize(String nonce, String userId, boolean approved) throws RepositoryException {
        return retrying(session -> {
            try { requireToken(nonce, "gon"); } catch (InvalidDelegationException e) { throw invalid(Refusal.EXPIRED); }
            String id = id(nonce);
            // Consents live under the signed-in user's own folder, so another user's nonce is simply not found.
            if (!id.startsWith(userKey(userId))) throw invalid(Refusal.EXPIRED);
            Node consent;
            try {
                consent = live(session, path(CONSENTS, id));
            } catch (InvalidDelegationException e) {
                throw invalid(Refusal.EXPIRED);
            }
            if (!userId.equals(string(consent, "userId")) || !matches(consent, "consentHash", nonce)) throw invalid(Refusal.EXPIRED);
            requireGrantUser(session, consent);
            String redirect = string(consent, "redirect");
            String state = string(consent, "state");
            String code = null;
            if (approved) {
                code = token("goc", id);
                Node folder = folder(session, ROOT, id);
                prune(folder, MAX_GRANTS_PER_USER, userId);
                Node grant = folder.addNode(id, CONTAINER);
                grant.setProperty("userId", userId);
                grant.setProperty("userIdentifier", string(consent, "userIdentifier"));
                grant.setProperty("configurationHash", configurationHash);
                grant.setProperty("redirect", redirect);
                grant.setProperty("challenge", string(consent, "challenge"));
                grant.setProperty("codeHash", hash(code));
                grant.setProperty("created", now());
                grant.setProperty("expires", now() + 60000);
                grant.setProperty("revision", random());
            }
            consent.remove();
            session.save();
            OboAudit.event(approved ? "consent_approved" : "consent_denied", userId, approved ? id : null, null);
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
                if (matches(grant, "usedCodeHash", code)) revokeFamily(session, grant, "code_replay");
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
            OboAudit.event("grant_issued", string(grant, "userId"), grant.getName(), null);
            return tokens;
        } finally { session.logout(); }
    }

    Tokens refresh(String refresh) throws RepositoryException {
        Session session = session();
        try {
            Node grant = grant(session, refresh, "gor");
            if (!matches(grant, "refreshHash", refresh)) {
                if (consumed(grant, refresh)) revokeFamily(session, grant, "refresh_replay");
                throw invalid();
            }
            requireGrantUser(session, grant);
            long rotations = grant.hasProperty("rotations") ? grant.getProperty("rotations").getLong() : 0;
            if (rotations >= MAX_ROTATIONS) throw invalid();
            grant.setProperty("rotations", rotations + 1);
            grant.setProperty("usedRefreshHashes", remember(grant, hash(refresh)));
            Tokens tokens = rotate(grant);
            session.save();
            OboAudit.debug("grant_refreshed", string(grant, "userId"), grant.getName());
            return tokens;
        } catch (InvalidItemStateException e) {
            // A concurrent rotation must not let a consumed refresh credential remain reusable.
            session.refresh(false);
            Node grant = grant(session, refresh, "gor");
            if (consumed(grant, refresh)) revokeFamily(session, grant, "refresh_race");
            throw invalid();
        } finally { session.logout(); }
    }

    void revoke(String token) throws RepositoryException {
        if (token == null || !TOKEN.matcher(token).matches()) return;
        Session session = session();
        try {
            String path = path(ROOT, id(token));
            if (!session.nodeExists(path)) return;
            Node grant = session.getNode(path);
            if (!configurationHash.equals(string(grant, "configurationHash"))) return;
            if (matches(grant, "accessHash", token) || matches(grant, "refreshHash", token) || consumed(grant, token)) {
                revokeFamily(session, grant, "disconnect");
            }
        } finally { session.logout(); }
    }

    /**
     * The per-request check, run once by the login module on its own system root. Returns the user whose
     * principals the request gets. Group membership and administrator status are checked there, on the
     * full principal set.
     */
    String validateAccess(Records records, UserManager users, String access) throws RepositoryException {
        requireToken(access, "goa");
        Record grant = records.get(path(ROOT, id(access)));
        long now = now();
        if (!enabled() || grant == null || !configurationHash.equals(grant.string("configurationHash"))
                || grant.flag("revoked") || expired(grant.number("expires", 0), grant.number("created", -1), now)
                || !equal(nullToEmpty(grant.string("accessHash")), hash(access))
                || grant.number("accessExpires", 0) <= now) throw invalid();
        String userId = grant.string("userId");
        if (userId == null || !id(access).startsWith(userKey(userId))) throw invalid();
        if (!nullToEmpty(grant.string("userIdentifier")).equals(userIdentifier(records, users, userId))) throw invalid();
        return userId;
    }

    private boolean expired(long expires, long created, long now) {
        // Lowering grantSeconds shortens live grants; raising it never extends one past its stored expiry.
        return expires <= now || (created > 0 && created + config.grantSeconds() * 1000L <= now);
    }

    private void revokeFamily(Session session, Node grant, String reason) throws RepositoryException {
        grant.setProperty("revoked", true);
        grant.setProperty("revision", random());
        session.save();
        OboAudit.event("grant_revoked", string(grant, "userId"), grant.getName(), "reason=" + reason);
    }

    private static boolean consumed(Node grant, String token) throws RepositoryException {
        if (!grant.hasProperty("usedRefreshHashes")) return false;
        String expected = hash(token);
        boolean found = false;
        for (javax.jcr.Value value : grant.getProperty("usedRefreshHashes").getValues()) {
            found |= equal(value.getString(), expected);
        }
        return found;
    }

    private static String[] remember(Node grant, String used) throws RepositoryException {
        List<String> history = new ArrayList<>();
        if (grant.hasProperty("usedRefreshHashes")) {
            for (javax.jcr.Value value : grant.getProperty("usedRefreshHashes").getValues()) history.add(value.getString());
        }
        history.add(used);
        List<String> kept = history.subList(Math.max(0, history.size() - REFRESH_HISTORY), history.size());
        return kept.toArray(new String[0]);
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
        Node grant = live(session, path(ROOT, id(token)));
        if (grant.hasProperty("revoked") && grant.getProperty("revoked").getBoolean()) throw invalid();
        return grant;
    }

    /** A stored record that belongs to this configuration and has not expired. */
    private Node live(Session session, String path) throws RepositoryException {
        if (!enabled() || !session.nodeExists(path)) throw invalid();
        Node node = session.getNode(path);
        if (!configurationHash.equals(string(node, "configurationHash"))
                || expired(number(node, "expires"), node.hasProperty("created") ? number(node, "created") : -1, now())) {
            throw invalid();
        }
        return node;
    }

    /**
     * Keeps at most {@code max - 1} live records so the new one makes {@code max}; the oldest go first.
     * Expired and revoked records are dropped on the way.
     */
    private void prune(Node folder, int max, String userId) throws RepositoryException {
        List<Node> live = new ArrayList<>();
        NodeIterator nodes = folder.getNodes();
        long now = now();
        while (nodes.hasNext()) {
            Node node = nodes.nextNode();
            if (removable(node, now)) node.remove(); else live.add(node);
        }
        live.sort(Comparator.comparingLong(OboService::created));
        for (int i = 0; live.size() - i >= max; i++) {
            if (userId != null) OboAudit.event("grant_evicted", userId, live.get(i).getName(), "reason=per_user_cap");
            live.get(i).remove();
        }
    }

    private static boolean removable(Node node, long now) throws RepositoryException {
        return (node.hasProperty("expires") && node.getProperty("expires").getLong() <= now)
                || (node.hasProperty("revoked") && node.getProperty("revoked").getBoolean());
    }

    private static void requireToken(String token, String prefix) throws RepositoryException {
        if (token == null || !TOKEN.matcher(token).matches() || !token.startsWith(prefix + "_")) throw invalid();
    }

    private static long created(Node node) {
        try { return node.hasProperty("created") ? node.getProperty("created").getLong() : 0; }
        catch (RepositoryException e) { return 0; }
    }

    private static Node folder(Session session, String root, String id) throws RepositoryException {
        return child(child(session.getNode(root), id.substring(0, 2)), id.substring(0, 16));
    }

    private static Node child(Node parent, String name) throws RepositoryException {
        return parent.hasNode(name) ? parent.getNode(name) : parent.addNode(name, CONTAINER);
    }

    /** First 16 hex characters of the user's hash: the user's folder, and the prefix of every record id. */
    static String userKey(String userId) { return hash(userId).substring(0, 16); }
    static String bucket(String key) { return hash(key).substring(0, 2); }
    static String path(String root, String id) { return root + "/" + id.substring(0, 2) + "/" + id.substring(0, 16) + "/" + id; }
    static String recordId(String userId) { return userKey(userId) + random(20); }

    private interface Operation<T> { T run(Session session) throws RepositoryException; }

    /** Retries when a concurrent writer (a sibling request or the cleanup job) created or removed a shared folder. */
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
        requireUser(users(session), userId);
    }

    void requireUser(UserManager users, String userId) throws RepositoryException {
        if (userId == null || "anonymous".equals(userId) || userId.startsWith("oauth-")) throw invalid(Refusal.ACCOUNT);
        Authorizable authorizable = users.getAuthorizable(userId);
        if (!(authorizable instanceof User) || ((User) authorizable).isSystemUser() || ((User) authorizable).isDisabled()) {
            throw invalid(Refusal.ACCOUNT);
        }
        // Delegation maps to the user's own principals, and for administrators that bypasses every ACL.
        if (!allowAdministrators() && administrator((User) authorizable)) {
            OboAudit.event("delegation_refused", userId, null, "reason=administrator");
            throw invalid(Refusal.ADMINISTRATOR);
        }
    }

    private static boolean administrator(User user) throws RepositoryException {
        if (user.isAdmin()) return true;
        // Transitive; the service user can read member-reference lists, so large groups are covered too.
        Iterator<Group> groups = user.memberOf();
        while (groups != null && groups.hasNext()) {
            if (ADMINISTRATORS.equals(groups.next().getID())) return true;
        }
        return false;
    }

    /** The user node identifier plus its protected creation time, so a recreated username differs. */
    String userIdentifier(Records records, UserManager users, String userId) throws RepositoryException {
        requireUser(users, userId);
        Authorizable user = users.getAuthorizable(userId);
        Record node = user == null ? null : records.get(user.getPath());
        long created = node == null ? -1 : node.date("jcr:created");
        if (node == null || node.identifier() == null || created < 0) throw invalid();
        return node.identifier() + ":" + created;
    }

    private void requireGrantUser(Session session, Node grant) throws RepositoryException {
        // Recreating the same username must never inherit a previous person's delegation.
        if (!string(grant, "userIdentifier").equals(userIdentifier(records(session), users(session), string(grant, "userId")))) {
            throw invalid();
        }
    }

    private static UserManager users(Session session) throws RepositoryException {
        if (!(session instanceof JackrabbitSession)) throw invalid();
        return ((JackrabbitSession) session).getUserManager();
    }

    private Session session() throws RepositoryException { return repository.loginService("obo", null); }
    static long now() { return System.currentTimeMillis(); }
    static String id(String token) { return token.substring(4, token.indexOf('.')); }
    private static String token(String prefix, String id) { return prefix + "_" + id + "." + random(); }
    static String random() { return random(32); }
    private static String random(int bytes) {
        byte[] value = new byte[bytes];
        RANDOM.nextBytes(value);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }
    static String challenge(String verifier) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest(verifier));
    }
    static String hash(String value) {
        StringBuilder hex = new StringBuilder(64);
        for (byte b : digest(value)) hex.append(String.format("%02x", b & 255));
        return hex.toString();
    }
    /** Short, non-reversible handle for logs. Never log a token or a record id that a token embeds. */
    static String fingerprint(String id) { return id == null ? "-" : hash("grant:" + id).substring(0, 12); }
    private static byte[] digest(String value) {
        try { return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)); }
        catch (NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }
    static boolean equal(String expected, String actual) {
        return MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8), actual.getBytes(StandardCharsets.UTF_8));
    }
    private static String nullToEmpty(String value) { return value == null ? "" : value; }
    private static boolean matches(Node node, String property, String token) throws RepositoryException {
        return node.hasProperty(property) && equal(string(node, property), hash(token));
    }
    private static String string(Node node, String property) throws RepositoryException { return node.getProperty(property).getString(); }
    private static long number(Node node, String property) throws RepositoryException { return node.getProperty(property).getLong(); }
    static InvalidDelegationException invalid() { return new InvalidDelegationException(Refusal.INVALID); }
    static InvalidDelegationException invalid(Refusal refusal) { return new InvalidDelegationException(refusal); }
    static final class InvalidDelegationException extends RepositoryException {
        private static final long serialVersionUID = 1L;
        private final Refusal refusal;
        InvalidDelegationException(Refusal refusal) {
            super("Invalid or expired delegation");
            this.refusal = refusal;
        }
        Refusal refusal() { return refusal; }
    }

    /**
     * Why an authorization request was refused, as an OAuth error code plus a description that names
     * the cause for the person and for Gradial, without revealing configuration.
     */
    enum Refusal {
        UNKNOWN_CLIENT("invalid_request", "client_id is not the one configured on this AEM"),
        UNREGISTERED_REDIRECT("invalid_request", "redirect_uri is not registered"),
        RESPONSE_TYPE("unsupported_response_type", "response_type must be code"),
        PKCE("invalid_request", "PKCE S256 required"),
        STATE("invalid_request", "state is missing or invalid"),
        MALFORMED("invalid_request", "a request parameter is missing, repeated or too long"),
        ADMINISTRATOR("access_denied", "administrators can't connect; sign in to AEM as your own user"),
        IMPERSONATION("access_denied", "stop impersonating another user in AEM, then connect as yourself"),
        DELEGATED_SESSION("access_denied", "a Gradial delegated session can't approve another connection"),
        ACCOUNT("access_denied", "this AEM account can't connect"),
        DECLINED("access_denied", "the user declined the connection"),
        EXPIRED("invalid_request", "sign-in expired, start again"),
        ORIGIN("invalid_request", "the approval did not come from this AEM sign-in page"),
        DISABLED("temporarily_unavailable", "user delegation is not enabled on this AEM"),
        UNAVAILABLE("temporarily_unavailable", "AEM could not complete the request, try again"),
        INVALID("invalid_request", "the request is invalid");

        final String error;
        final String description;
        Refusal(String error, String description) { this.error = error; this.description = description; }
        /** The callback cannot be trusted with these, so they stay on the AEM page (RFC 6749 4.1.2.1). */
        boolean inPage() { return this == UNKNOWN_CLIENT || this == UNREGISTERED_REDIRECT || this == DISABLED; }
    }

    /** Read-only view of stored records, over a JCR session or an Oak root. */
    interface Records {
        /** The record at an absolute path, or null when it does not exist or cannot be read. */
        Record get(String path) throws RepositoryException;
    }

    interface Record {
        String identifier() throws RepositoryException;
        /** Null when absent. */
        String string(String name) throws RepositoryException;
        long number(String name, long absent) throws RepositoryException;
        boolean flag(String name) throws RepositoryException;
        /** Milliseconds, or -1 when absent. */
        long date(String name) throws RepositoryException;
    }

    static Records records(Session session) {
        return path -> {
            if (!session.nodeExists(path)) return null;
            Node node = session.getNode(path);
            return new Record() {
                @Override public String identifier() throws RepositoryException { return node.getIdentifier(); }
                @Override public String string(String name) throws RepositoryException {
                    return node.hasProperty(name) ? node.getProperty(name).getString() : null;
                }
                @Override public long number(String name, long absent) throws RepositoryException {
                    return node.hasProperty(name) ? node.getProperty(name).getLong() : absent;
                }
                @Override public boolean flag(String name) throws RepositoryException {
                    return node.hasProperty(name) && node.getProperty(name).getBoolean();
                }
                @Override public long date(String name) throws RepositoryException {
                    return node.hasProperty(name) ? node.getProperty(name).getDate().getTimeInMillis() : -1;
                }
            };
        };
    }

    @Override
    public void run() {
        if (!enabled()) return;
        long deadline = now() + CLEANUP_BUDGET_MS;
        int removed = 0;
        try {
            Session session = session();
            try {
                Node grants = session.getNode(ROOT);
                Node consents = session.getNode(CONSENTS);
                int start = cleanupCursor;
                int next = 0;
                Counter pending = new Counter(session);
                // No count cap: every bucket is swept. Only a time budget stops a pass, and the next one resumes there.
                for (int i = 0; i < BUCKETS; i++) {
                    int index = (start + i) % BUCKETS;
                    if (i > 0 && now() > deadline) { next = index; break; }
                    String name = String.format("%02x", index);
                    if (grants.hasNode(name)) sweep(grants.getNode(name), pending);
                    if (consents.hasNode(name)) sweep(consents.getNode(name), pending);
                }
                session.save();
                removed = pending.total;
                cleanupCursor = next;
            } finally { session.logout(); }
            if (removed > 0) LOG.debug("User-delegation cleanup removed {} expired or revoked records", removed);
        } catch (RepositoryException e) {
            LOG.warn("User-delegation cleanup failed; the next run retries", e);
        }
    }

    /** Saves every {@link #SAVE_BATCH} removals so no commit grows with the size of the store. */
    private static final class Counter {
        private final Session session;
        private int sinceSave;
        int total;
        Counter(Session session) { this.session = session; }
        void removed(Node node) throws RepositoryException {
            node.remove();
            total++;
            if (++sinceSave >= SAVE_BATCH) { session.save(); sinceSave = 0; }
        }
    }

    private static void sweep(Node bucket, Counter pending) throws RepositoryException {
        long now = now();
        NodeIterator users = bucket.getNodes();
        while (users.hasNext()) {
            Node user = users.nextNode();
            if (user.hasProperty("configurationHash")) {
                // A record directly in a bucket comes from a pre-release layout and can no longer be reached.
                pending.removed(user);
                continue;
            }
            NodeIterator records = user.getNodes();
            while (records.hasNext()) {
                Node record = records.nextNode();
                if (removable(record, now)) pending.removed(record);
            }
            if (!user.hasNodes()) pending.removed(user);
        }
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
