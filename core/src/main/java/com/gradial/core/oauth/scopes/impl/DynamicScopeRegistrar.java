package com.gradial.core.oauth.scopes.impl;

import java.util.Collection;
import java.util.Collections;
import java.util.Dictionary;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import javax.jcr.RepositoryException;
import javax.jcr.Session;

import org.apache.jackrabbit.api.security.user.User;
import org.apache.sling.api.resource.LoginException;
import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.api.resource.ResourceResolverFactory;
import org.apache.sling.api.resource.observation.ResourceChange;
import org.apache.sling.api.resource.observation.ExternalResourceChangeListener;
import org.apache.sling.api.resource.observation.ResourceChangeListener;
import org.apache.sling.serviceusermapping.ServiceUserMapped;
import org.osgi.framework.Bundle;
import org.osgi.framework.BundleContext;
import org.osgi.framework.InvalidSyntaxException;
import org.osgi.framework.ServiceReference;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.ConfigurationPolicy;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.osgi.service.component.annotations.ReferencePolicyOption;
import org.osgi.service.metatype.annotations.Designate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.adobe.granite.oauth.server.Scope;
import com.gradial.core.oauth.config.DynamicOAuthScopeConfiguration;
import com.gradial.core.oauth.scopes.DynamicScope;

/**
 * Registers one {@link DynamicScope} with Granite OAuth per factory configuration, and reports when the
 * scope's resource path is missing.
 *
 * <ul>
 * <li><b>Name must be free.</b> Granite OAuth 1.1.34 keeps one scope per name: a later registration
 * replaces an earlier one and unregistering either removes the name. A name another scope service already
 * holds is therefore refused with one ERROR naming both, instead of silently replacing it.</li>
 * <li><b>Missing path is reported, never refused.</b> If the resource path does not exist, or is not
 * visible to {@value #READER}, the scope still registers and one ERROR names the scope and the path. Granite
 * then issues tokens for it as before. Visibility never decides registration, so a read-permission setting
 * cannot turn into a broken integration; the user-facing message is Gradial's own health check.
 * An existing path is hidden from the reader only by a deny entry for that user itself, or by a closed user
 * group ({@code rep:cugPolicy}) on the path or an ancestor where CUG evaluation is enabled (Oak's
 * {@code CugConfiguration} has {@code cugEnabled=false} by default, as on Author). A {@code deny jcr:read}
 * for {@code everyone} does not hide it: Oak evaluates entries for user principals before entries for group
 * principals at every level (oak-core 1.88.0 {@code CompiledPermissionImpl.java:436-444},
 * {@code chainedIterator(userEntries, groupEntries)}), so the reader's own {@code allow rep:readNodes} on
 * {@code /} wins.</li>
 * </ul>
 *
 * <p>The path is checked at activation, when a Sling {@link ResourceChangeListener} reports the path or an
 * ancestor ADDED or REMOVED, when the reader becomes available ({@link ScopeReaderReady} or the
 * {@code scope-check} {@link ServiceUserMapped} binds), and when Granite reads the resource path to issue a
 * token (rate-limited). ERROR and INFO are logged only on a change of state.
 *
 * <p>Existence is read as the {@value #SUBSERVICE} service user, which has {@code rep:readNodes} only.
 * Until that user can log in, the scope registers with one WARN that the path is unchecked.
 *
 * <p>It is an {@link ExternalResourceChangeListener}, so a path created or removed on another node of a
 * clustered Author is reported here too.
 *
 * <p>Deliberately has no {@code @Modified}: Granite keys scopes by the name read at bind time, so a
 * configuration change must deactivate and reactivate this component to re-register under the new name.
 */
@Component(
        // No declarative service: the scope and a path-scoped listener are registered programmatically.
        service = {},
        configurationPid = "com.gradial.core.oauth.scopes.DynamicScope",
        configurationPolicy = ConfigurationPolicy.REQUIRE,
        immediate = true
)
@Designate(ocd = DynamicOAuthScopeConfiguration.class, factory = true)
public class DynamicScopeRegistrar implements ResourceChangeListener, ExternalResourceChangeListener {

    private static final Logger LOGGER = LoggerFactory.getLogger(DynamicScopeRegistrar.class);
    /** Service user mapping of this bundle used only to test that resource paths exist. */
    static final String SUBSERVICE = "scope-check";
    static final String READER = "gradial-oauth-scope-reader";
    /** Service property naming the scope, for diagnostics in the web console. */
    static final String SCOPE_NAME_PROPERTY = "gradial.oauth.scope.name";
    /** At most one token-time ERROR per scope in this interval. */
    static final long TOKEN_ERROR_INTERVAL_MS = 15 * 60 * 1000L;
    /** Serializes check-and-register across all configurations, so two cannot claim one name at once. */
    private static final Object REGISTRATION = new Object();

    @Reference
    private ResourceResolverFactory resolverFactory;

    private volatile DynamicOAuthScopeConfiguration config;
    private BundleContext bundleContext;
    private ConfiguredScope scope;
    private ServiceRegistration<?> listener;
    private ServiceRegistration<?> registration;
    private boolean active;
    /** Last known PRESENT or MISSING; null until a check could log in. Guarded by this. */
    private Existence known;
    private boolean warnedUnchecked;
    private final AtomicLong lastTokenError = new AtomicLong(Long.MIN_VALUE / 2);

    @Activate
    protected void activate(BundleContext context, DynamicOAuthScopeConfiguration config) {
        this.bundleContext = context;
        this.scope = new ConfiguredScope(this, config);
        synchronized (REGISTRATION) {
            active = true;
        }
        this.config = config;
        Dictionary<String, Object> properties = new Hashtable<>();
        properties.put(ResourceChangeListener.PATHS, listenerPaths(config.resourcePath()));
        properties.put(ResourceChangeListener.CHANGES, new String[] {"ADDED", "REMOVED"});
        listener = context.registerService(ResourceChangeListener.class.getName(), this, properties);
        reconcile();
    }

    /**
     * Re-checks the path once {@link ScopeReaderRepositoryInitializer} has created the reader. Optional and
     * dynamic, so a missing or colliding reader never blocks the scope; greedy, so a marker registered after
     * activation is bound.
     */
    @Reference(service = ScopeReaderReady.class, cardinality = ReferenceCardinality.OPTIONAL,
            policy = ReferencePolicy.DYNAMIC, policyOption = ReferencePolicyOption.GREEDY)
    void bindScopeReaderReady(ScopeReaderReady ready) {
        if (config != null) reconcile();
    }

    void unbindScopeReaderReady(ScopeReaderReady ready) {
        // Nothing to undo: the scope stays registered.
    }

    /**
     * Re-checks the path when this bundle's {@value #SUBSERVICE} mapping becomes active, which covers a mapping
     * configuration that arrives after the user already exists. Sling's ServiceUserMappedBundleFilter shows each
     * bundle only its own mappings, so the subservice name is enough as target.
     */
    @Reference(service = ServiceUserMapped.class, target = "(" + ServiceUserMapped.SUBSERVICENAME + "=" + SUBSERVICE + ")",
            cardinality = ReferenceCardinality.OPTIONAL, policy = ReferencePolicy.DYNAMIC,
            policyOption = ReferencePolicyOption.GREEDY)
    void bindServiceUserMapped(ServiceUserMapped mapped) {
        if (config != null) reconcile();
    }

    void unbindServiceUserMapped(ServiceUserMapped mapped) {
        // Nothing to undo: the scope stays registered.
    }

    /**
     * The path itself (its removal, and the removal of an ancestor, are reported there), plus each ancestor's
     * direct children as a glob. Oak filters change sets by the parent path of a change, so the creation of the
     * path, or of a missing ancestor, is reported only to a listener on that parent; a direct-children glob
     * sees it without subscribing to the whole subtree below each ancestor.
     */
    static String[] listenerPaths(String resourcePath) {
        java.util.List<String> paths = new java.util.ArrayList<>();
        paths.add(resourcePath);
        String parent = resourcePath;
        while (parent.lastIndexOf('/') > 0) {
            parent = parent.substring(0, parent.lastIndexOf('/'));
            paths.add("glob:" + parent + "/*");
        }
        if (!"/".equals(resourcePath)) paths.add("glob:/*");
        return paths.toArray(new String[0]);
    }

    @Deactivate
    protected void deactivate() {
        synchronized (REGISTRATION) {
            active = false;
            unregister();
        }
        if (listener != null) {
            listener.unregister();
            listener = null;
        }
    }

    @Override
    public void onChange(List<ResourceChange> changes) {
        String path = config.resourcePath();
        if (LOGGER.isDebugEnabled()) {
            for (ResourceChange change : changes) {
                LOGGER.debug("OAuth scope {}: {} {}", config.scopeName(), change.getType(), change.getPath());
            }
        }
        for (ResourceChange change : changes) {
            String changed = change.getPath();
            if (path.equals(changed) || path.startsWith(changed + "/")) {
                reconcile();
                return;
            }
        }
    }

    /** Registers the scope if its name is free, and logs a change of its path's state. */
    void reconcile() {
        // The check and the logging happen under one per-scope lock, so a slower, older check can never be
        // reported after a newer one. REGISTRATION is always taken inside it, never the other way round.
        synchronized (this) {
            Existence existence = existence();
            if (!register()) return;
            report(existence);
        }
    }

    /** True when this scope is registered (now or already); false when inactive or the name is taken. */
    private boolean register() {
        synchronized (REGISTRATION) {
            if (!active) return false;
            if (registration != null) return true;
            String holder = holderOfName();
            if (holder != null) {
                LOGGER.error("OAuth scope {} not registered: the name is already registered by {}. Granite keeps one "
                        + "scope per name, so registering it would silently replace that scope. Remove one of the two "
                        + "definitions (this one is a {} configuration in {}).", config.scopeName(), holder,
                        DynamicScope.class.getName(), describe(bundleContext.getBundle()));
                return false;
            }
            Dictionary<String, Object> properties = new Hashtable<>();
            properties.put(SCOPE_NAME_PROPERTY, config.scopeName());
            registration = bundleContext.registerService(Scope.class.getName(), scope, properties);
            return true;
        }
    }

    /** Logs the path's state when it changes. Caller holds this. */
    private void report(Existence existence) {
        if (existence == Existence.UNKNOWN) {
            if (known == null && !warnedUnchecked) {
                warnedUnchecked = true;
                LOGGER.warn("OAuth scope {} registered without checking that {} exists: the {} service user of {} cannot "
                        + "log in yet. The path is checked when it can.", config.scopeName(), config.resourcePath(),
                        SUBSERVICE, bundleContext.getBundle().getSymbolicName());
            }
            return;
        }
        if (existence == known) return;
        if (existence == Existence.MISSING) {
            LOGGER.error(missingMessage(), config.scopeName(), config.resourcePath(), READER);
        } else if (known == Existence.MISSING) {
            LOGGER.info("OAuth scope {}: resource path {} exists again.", config.scopeName(), config.resourcePath());
        }
        known = existence;
    }

    private static String missingMessage() {
        return "OAuth scope {} is registered, but its resource path {} is missing or not visible to {} (only a deny "
                + "entry for that user, or a closed user group where CUG evaluation is enabled, can hide an existing path). "
                + "Tokens for this scope are still issued; they grant nothing under the path while it is missing.";
    }

    boolean registered() {
        synchronized (REGISTRATION) {
            return registration != null;
        }
    }

    private void unregister() {
        if (registration != null) {
            try {
                registration.unregister();
            } catch (IllegalStateException alreadyGone) {
                // The bundle is stopping and the framework already removed it.
            }
            registration = null;
        }
    }

    /** Token-time check: never refuses; logs at most once per {@link #TOKEN_ERROR_INTERVAL_MS} per scope. */
    void checkAtTokenIssue(String path) {
        if (existence() != Existence.MISSING) return;
        long now = System.currentTimeMillis();
        long last = lastTokenError.get();
        if (now - last >= TOKEN_ERROR_INTERVAL_MS && lastTokenError.compareAndSet(last, now)) {
            LOGGER.error(missingMessage(), config.scopeName(), path, READER);
        }
    }

    enum Existence { PRESENT, MISSING, UNKNOWN }

    /** Whether the resource path exists, read as this bundle's existence-check service user. */
    Existence existence() {
        Map<String, Object> auth = Collections.singletonMap(ResourceResolverFactory.SUBSERVICE, (Object) SUBSERVICE);
        try (ResourceResolver resolver = resolverFactory.getServiceResourceResolver(auth)) {
            Session session = resolver.adaptTo(Session.class);
            // nodeExists needs only node read (rep:readNodes), not property read.
            boolean exists = session != null ? session.nodeExists(config.resourcePath())
                    : resolver.getResource(config.resourcePath()) != null;
            return exists ? Existence.PRESENT : Existence.MISSING;
        } catch (RepositoryException e) {
            LOGGER.warn("OAuth scope {}: could not check resource path {}", config.scopeName(), config.resourcePath(), e);
            return Existence.UNKNOWN;
        } catch (LoginException e) {
            // Without the service user, keep the previous behavior (register) rather than drop every scope.
            return Existence.UNKNOWN;
        }
    }

    /** Another scope service that already holds this scope's name, described for the log; null if none. */
    private String holderOfName() {
        Collection<ServiceReference<Scope>> references;
        try {
            references = bundleContext.getServiceReferences(Scope.class, null);
        } catch (InvalidSyntaxException e) {
            throw new IllegalStateException(e);
        }
        for (ServiceReference<Scope> reference : references) {
            Scope other = bundleContext.getService(reference);
            if (other == null) continue;
            try {
                if (other != scope && config.scopeName().equals(other.getName())) {
                    Object component = reference.getProperty("component.name");
                    Object pid = reference.getProperty("service.pid");
                    return describe(reference.getBundle()) + " (" + (component != null ? component : other.getClass().getName())
                            + (pid != null ? ", " + pid : "") + ")";
                }
            } catch (RuntimeException e) {
                // A broken foreign scope must not stop this one from registering.
            } finally {
                bundleContext.ungetService(reference);
            }
        }
        return null;
    }

    private static String describe(Bundle bundle) {
        return bundle == null ? "an unknown bundle" : bundle.getSymbolicName() + " [" + bundle.getBundleId() + "]";
    }

    /** The registered scope: a {@link DynamicScope} that reports a missing path when a token is issued. */
    static final class ConfiguredScope extends DynamicScope {
        private final DynamicScopeRegistrar registrar;

        ConfiguredScope(DynamicScopeRegistrar registrar, DynamicOAuthScopeConfiguration config) {
            this.registrar = registrar;
            activate(config);
        }

        /**
         * Called by Granite when it issues a token. Returns the configured path as before, and logs (rate-limited)
         * when the path has gone or is hidden, for example after an ancestor was deleted on a path the listener
         * cannot see. It never throws: a missing path must not change what Granite returns.
         */
        @Override
        public String getResourcePath(User user) {
            String path = super.getResourcePath(user);
            try {
                registrar.checkAtTokenIssue(path);
            } catch (RuntimeException e) {
                LOGGER.debug("OAuth scope {}: token-time path check failed", getName(), e);
            }
            return path;
        }
    }
}
