package com.gradial.core.oauth.scopes.impl;

import java.util.Collection;
import java.util.Collections;
import java.util.Dictionary;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;

import javax.jcr.RepositoryException;
import javax.jcr.Session;

import org.apache.jackrabbit.api.security.user.User;
import org.apache.sling.api.resource.LoginException;
import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.api.resource.ResourceResolverFactory;
import org.apache.sling.api.resource.observation.ResourceChange;
import org.apache.sling.api.resource.observation.ResourceChangeListener;
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
import org.osgi.service.metatype.annotations.Designate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.adobe.granite.oauth.server.Scope;
import com.gradial.core.oauth.config.DynamicOAuthScopeConfiguration;
import com.gradial.core.oauth.scopes.DynamicScope;

/**
 * Registers one {@link DynamicScope} with Granite OAuth per factory configuration, but only while the
 * scope can work.
 *
 * <ul>
 * <li><b>Resource path must exist.</b> Granite grants a token nothing at all when one requested
 * scope's path is missing, and still issues the token. An unregistered scope instead fails the token
 * request with {@code invalid_scope}. A Sling {@link ResourceChangeListener} on the path registers the
 * scope when the path is created and unregisters it when the path is removed, without a restart. At
 * token issue the scope checks the path again, which also covers removal of an ancestor.</li>
 * <li><b>Name must be free.</b> Granite keeps one scope per name: a later registration replaces an
 * earlier one and unregistering either removes the name. A name another scope already holds is
 * therefore refused with an error naming both, instead of silently replacing it.</li>
 * </ul>
 *
 * <p>Existence is read as the {@value #SUBSERVICE} service user, which has {@code rep:readNodes} only.
 * Without that service user the scope registers as before, with one warning, so a deployment that
 * lacks this package's configurations keeps its scopes.
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
public class DynamicScopeRegistrar implements ResourceChangeListener {

    private static final Logger LOGGER = LoggerFactory.getLogger(DynamicScopeRegistrar.class);
    /** Service user mapping of this bundle used only to test that resource paths exist. */
    static final String SUBSERVICE = "scope-check";
    static final String READER = "gradial-oauth-scope-reader";
    /** Service property naming the scope, for diagnostics in the web console. */
    static final String SCOPE_NAME_PROPERTY = "gradial.oauth.scope.name";
    /** Serializes check-and-register across all configurations, so two cannot claim one name at once. */
    private static final Object REGISTRATION = new Object();

    @Reference
    private ResourceResolverFactory resolverFactory;

    private DynamicOAuthScopeConfiguration config;
    private BundleContext bundleContext;
    private ConfiguredScope scope;
    private ServiceRegistration<?> listener;
    private ServiceRegistration<?> registration;
    private boolean active;

    @Activate
    protected void activate(BundleContext context, DynamicOAuthScopeConfiguration config) {
        this.bundleContext = context;
        this.config = config;
        this.scope = new ConfiguredScope(this, config);
        synchronized (REGISTRATION) {
            active = true;
        }
        Dictionary<String, Object> properties = new Hashtable<>();
        properties.put(ResourceChangeListener.PATHS, listenerPaths(config.resourcePath()));
        properties.put(ResourceChangeListener.CHANGES, new String[] {"ADDED", "REMOVED"});
        listener = context.registerService(ResourceChangeListener.class.getName(), this, properties);
        reconcile(true);
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
                reconcile(false);
                return;
            }
        }
    }

    /** Registers the scope when its path exists and its name is free; unregisters it otherwise. */
    void reconcile(boolean logMissing) {
        Existence existence = existence();
        synchronized (REGISTRATION) {
            if (!active) return;
            if (existence == Existence.MISSING) {
                if (registration != null) {
                    LOGGER.error("OAuth scope {} unregistered: its resource path {} no longer exists. Token requests for "
                            + "this scope now fail with invalid_scope until the path exists again.",
                            config.scopeName(), config.resourcePath());
                    unregister();
                } else if (logMissing) {
                    LOGGER.error("OAuth scope {} not registered: its resource path {} does not exist (or is not visible to {}). "
                            + "Token requests for this scope fail with invalid_scope; it registers automatically when the "
                            + "path is created.", config.scopeName(), config.resourcePath(), READER);
                }
                return;
            }
            if (registration != null) return;
            String holder = holderOfName();
            if (holder != null) {
                LOGGER.error("OAuth scope {} not registered: the name is already registered by {}. Granite keeps one "
                        + "scope per name, so registering it would silently replace that scope. Remove one of the two "
                        + "definitions (this one is a {} configuration in {}).", config.scopeName(), holder,
                        DynamicScope.class.getName(), describe(bundleContext.getBundle()));
                return;
            }
            Dictionary<String, Object> properties = new Hashtable<>();
            properties.put(SCOPE_NAME_PROPERTY, config.scopeName());
            registration = bundleContext.registerService(Scope.class.getName(), scope, properties);
            if (existence == Existence.UNKNOWN) {
                LOGGER.warn("OAuth scope {} registered without checking that {} exists: the {} service user of {} is not "
                        + "available. Install this package's repoinit and service mapping configurations.",
                        config.scopeName(), config.resourcePath(), SUBSERVICE, bundleContext.getBundle().getSymbolicName());
            }
        }
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

    /** The registered scope: a {@link DynamicScope} that re-checks its path when a token is issued. */
    static final class ConfiguredScope extends DynamicScope {
        private final DynamicScopeRegistrar registrar;

        ConfiguredScope(DynamicScopeRegistrar registrar, DynamicOAuthScopeConfiguration config) {
            this.registrar = registrar;
            activate(config);
        }

        /**
         * Called by Granite when it issues a token. If the path has gone (for example an ancestor was
         * deleted, which the listener does not see), the scope unregisters and the token request fails
         * instead of returning a token with no access.
         */
        @Override
        public String getResourcePath(User user) {
            String path = super.getResourcePath(user);
            if (registrar.existence() == Existence.MISSING) {
                registrar.reconcile(false);
                throw new IllegalStateException("OAuth scope " + getName() + " cannot be granted: resource path "
                        + path + " does not exist");
            }
            return path;
        }
    }
}
