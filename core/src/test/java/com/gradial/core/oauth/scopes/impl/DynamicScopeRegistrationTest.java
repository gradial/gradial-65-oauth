package com.gradial.core.oauth.scopes.impl;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import org.apache.sling.api.resource.LoginException;
import org.apache.sling.api.resource.ResourceResolverFactory;
import org.apache.sling.api.resource.observation.ResourceChange;
import org.apache.sling.api.resource.observation.ResourceChangeListener;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import com.adobe.granite.oauth.server.Scope;
import com.gradial.core.oauth.config.DynamicOAuthScopeConfiguration;

import io.wcm.testing.mock.aem.junit5.AemContext;
import io.wcm.testing.mock.aem.junit5.AemContextExtension;
import uk.org.lidalia.slf4jtest.LoggingEvent;
import uk.org.lidalia.slf4jtest.TestLogger;
import uk.org.lidalia.slf4jtest.TestLoggerFactory;

/** Registration rules for {@link DynamicScopeRegistrar}, on OSGi and Sling mocks. */
@ExtendWith(AemContextExtension.class)
class DynamicScopeRegistrationTest {
    private final AemContext context = new AemContext();
    private final TestLogger log = TestLoggerFactory.getTestLogger(DynamicScopeRegistrar.class);

    @AfterEach
    void clear() { TestLoggerFactory.clearAll(); }

    /** Creates and commits a resource, so the service resolver used for the existence check sees it. */
    private void path(String path) {
        context.create().resource(path);
        try { context.resourceResolver().commit(); } catch (Exception e) { throw new AssertionError(e); }
    }

    /** Activates one scope configuration through the registrar, as SCR does. */
    private DynamicScopeRegistrar registrar(String name, String path) {
        DynamicOAuthScopeConfiguration config = mock(DynamicOAuthScopeConfiguration.class);
        when(config.scopeName()).thenReturn(name);
        when(config.resourcePath()).thenReturn(path);
        when(config.requiredPrivileges()).thenReturn(new String[] {"jcr:read"});
        DynamicScopeRegistrar registrar = new DynamicScopeRegistrar();
        try {
            java.lang.reflect.Field f = DynamicScopeRegistrar.class.getDeclaredField("resolverFactory");
            f.setAccessible(true);
            f.set(registrar, context.getService(ResourceResolverFactory.class));
        } catch (ReflectiveOperationException e) { throw new AssertionError(e); }
        registrar.activate(context.bundleContext(), config);
        return registrar;
    }

    /** The scope instance Granite would see for this name, or null. */
    private Scope registered(String name) {
        for (Scope scope : context.getServices(Scope.class, null)) if (name.equals(scope.getName())) return scope;
        return null;
    }

    private List<String> registeredNames() {
        return Arrays.stream(context.getServices(Scope.class, null)).map(Scope::getName).collect(Collectors.toList());
    }

    private List<String> errors() {
        return log.getAllLoggingEvents().stream().filter(e -> e.getLevel() == uk.org.lidalia.slf4jext.Level.ERROR)
                .map(LoggingEvent::getMessage).collect(Collectors.toList());
    }

    private static List<ResourceChange> change(ResourceChange.ChangeType type, String path) {
        return Collections.singletonList(new ResourceChange(type, path, false));
    }

    @Test
    void aScopeWhosePathExistsIsRegistered() {
        path("/content/site");
        registrar("site_author", "/content/site");
        assertEquals(Collections.singletonList("site_author"), registeredNames());
        assertTrue(errors().isEmpty());
    }

    @Test
    void aScopeWhosePathIsMissingIsNotRegisteredAndLogsOneErrorNamingScopeAndPath() {
        registrar("site_author", "/content/missing");
        assertTrue(registeredNames().isEmpty());
        assertEquals(1, errors().size());
        LoggingEvent error = log.getAllLoggingEvents().stream()
                .filter(e -> e.getLevel() == uk.org.lidalia.slf4jext.Level.ERROR).findFirst().get();
        assertTrue(error.getArguments().contains("site_author"));
        assertTrue(error.getArguments().contains("/content/missing"));
    }

    @Test
    void theScopeRegistersWhenItsPathAppearsAndUnregistersWhenItIsRemoved() {
        DynamicScopeRegistrar scope = registrar("workflow_start", "/var/workflow/models/gradial");
        assertTrue(registeredNames().isEmpty());

        path("/var/workflow/models/gradial");
        scope.onChange(change(ResourceChange.ChangeType.ADDED, "/var/workflow/models/gradial"));
        assertEquals(Collections.singletonList("workflow_start"), registeredNames());

        context.resourceResolver().getResource("/var/workflow/models/gradial");
        org.apache.sling.api.resource.ResourceResolver resolver = context.resourceResolver();
        try {
            resolver.delete(resolver.getResource("/var/workflow/models/gradial"));
            resolver.commit();
        } catch (Exception e) { throw new AssertionError(e); }
        scope.onChange(change(ResourceChange.ChangeType.REMOVED, "/var/workflow/models/gradial"));
        assertTrue(registeredNames().isEmpty());
    }

    @Test
    void theListenerWatchesOnlyTheScopePathForAdditionsAndRemovals() {
        registrar("site_author", "/content/site");
        org.osgi.framework.ServiceReference<?>[] references = null;
        try {
            references = context.bundleContext().getServiceReferences(ResourceChangeListener.class.getName(), null);
        } catch (Exception e) { throw new AssertionError(e); }
        assertNotNull(references);
        boolean found = false;
        for (org.osgi.framework.ServiceReference<?> reference : references) {
            Object paths = reference.getProperty(ResourceChangeListener.PATHS);
            if (paths instanceof String[] && Arrays.asList((String[]) paths).contains("/content/site")) {
                found = true;
                assertEquals(Arrays.asList("/content/site", "glob:/content/*", "glob:/*"), Arrays.asList((String[]) paths),
                        "creation of the path or of an ancestor is reported to a listener on its parent");
                assertEquals(Arrays.asList("ADDED", "REMOVED"),
                        Arrays.asList((String[]) reference.getProperty(ResourceChangeListener.CHANGES)));
            }
        }
        assertTrue(found);
    }

    @Test
    void theComponentDeclaresNoServiceSoNoUnscopedListenerIsRegistered() {
        // bnd writes the descriptor into target/classes before tests run.
        java.nio.file.Path descriptor = java.nio.file.Paths.get("target/classes/OSGI-INF/"
                + DynamicScopeRegistrar.class.getName() + ".xml");
        String xml;
        try { xml = new String(java.nio.file.Files.readAllBytes(descriptor), java.nio.charset.StandardCharsets.UTF_8); }
        catch (java.io.IOException e) { throw new AssertionError(e); }
        assertTrue(xml.contains("configuration-pid=\"com.gradial.core.oauth.scopes.DynamicScope\""), "existing configurations still apply");
        assertFalse(xml.contains("<service"), "a declarative ResourceChangeListener would have no resource.paths");
    }

    @Test
    void listenerPathsWatchEachAncestorsDirectChildrenOnly() {
        assertEquals(Arrays.asList("/var/workflow/models/gradial", "glob:/var/workflow/models/*", "glob:/var/workflow/*",
                "glob:/var/*", "glob:/*"), Arrays.asList(DynamicScopeRegistrar.listenerPaths("/var/workflow/models/gradial")));
        assertEquals(Collections.singletonList("/"), Arrays.asList(DynamicScopeRegistrar.listenerPaths("/")));
    }

    @Test
    void aRemovalOfAnUnregisteredScopesPathLogsNothingNew() {
        DynamicScopeRegistrar scope = registrar("zz", "/content/missing");
        int before = errors().size();
        scope.onChange(change(ResourceChange.ChangeType.REMOVED, "/content/missing"));
        assertEquals(before, errors().size());
    }

    @Test
    void creatingAMissingAncestorRegistersTheScope() {
        DynamicScopeRegistrar scope = registrar("deep", "/content/new/site");
        path("/content/new/site");
        scope.onChange(change(ResourceChange.ChangeType.ADDED, "/content/new"));
        assertEquals(Collections.singletonList("deep"), registeredNames());
    }

    @Test
    void changesElsewhereAreIgnored() {
        DynamicScopeRegistrar scope = registrar("site_author", "/content/site");
        path("/content/other");
        scope.onChange(change(ResourceChange.ChangeType.ADDED, "/content/other"));
        assertTrue(registeredNames().isEmpty());
    }

    @Test
    void anAncestorRemovalFailsTheNextTokenAndUnregistersTheScope() {
        path("/content/site/en");
        DynamicScopeRegistrar scope = registrar("site_author", "/content/site/en");
        Scope granted = registered("site_author");
        assertEquals("/content/site/en", ((com.adobe.granite.oauth.server.ScopeWithPrivileges) granted).getResourcePath(null));
        org.apache.sling.api.resource.ResourceResolver resolver = context.resourceResolver();
        try {
            resolver.delete(resolver.getResource("/content/site"));
            resolver.commit();
        } catch (Exception e) { throw new AssertionError(e); }
        assertThrows(IllegalStateException.class, () -> granted.getResourcePath(null));
        assertTrue(registeredNames().isEmpty());
    }

    @Test
    void otherScopesKeepWorkingWhenOneIsRefused() {
        path("/content/site");
        registrar("broken", "/content/missing");
        DynamicScopeRegistrar valid = registrar("site_author", "/content/site");
        assertEquals(Collections.singletonList("site_author"), registeredNames());
        assertEquals("/content/site", registered("site_author").getResourcePath(null));
    }

    @Test
    void aNameAlreadyRegisteredByAnotherBundleIsRefusedWithAnErrorNamingBoth() {
        path("/content/site");
        Scope foreign = mock(Scope.class);
        when(foreign.getName()).thenReturn("read_all");
        context.registerService(Scope.class, foreign, "component.name", "com.example.ReadAllScope");
        registrar("read_all", "/content/site");
        assertEquals(Collections.singletonList("read_all"), registeredNames(), "only the foreign scope holds the name");
        assertSame(foreign, context.getService(Scope.class));
        assertEquals(1, errors().size());
        assertTrue(log.getAllLoggingEvents().stream().anyMatch(e -> e.getArguments().stream()
                .anyMatch(a -> String.valueOf(a).contains("com.example.ReadAllScope"))));
    }

    @Test
    void twoOfOurOwnConfigurationsCannotClaimTheSameName() {
        path("/content/a");
        path("/content/b");
        registrar("site_author", "/content/a");
        registrar("site_author", "/content/b");
        assertEquals(Collections.singletonList("site_author"), registeredNames());
        assertEquals(1, errors().size());
    }

    @Test
    void deactivationUnregistersTheScopeAndTheListener() {
        path("/content/site");
        DynamicScopeRegistrar scope = registrar("site_author", "/content/site");
        scope.deactivate();
        assertTrue(registeredNames().isEmpty());
        scope.onChange(change(ResourceChange.ChangeType.ADDED, "/content/site"));
        assertTrue(registeredNames().isEmpty(), "a deactivated scope never re-registers");
    }

    @Test
    void withoutTheServiceUserTheScopeStillRegistersAsBeforeWithOneWarning() throws Exception {
        ResourceResolverFactory unavailable = mock(ResourceResolverFactory.class);
        when(unavailable.getServiceResourceResolver(any())).thenThrow(new LoginException("no mapping"));
        context.registerService(ResourceResolverFactory.class, unavailable, "service.ranking", Integer.MAX_VALUE);
        DynamicScopeRegistrar scope = registrar("site_author", "/content/anything");
        assertEquals(Collections.singletonList("site_author"), registeredNames());
        assertEquals("/content/anything", registered("site_author").getResourcePath(null));
        assertTrue(errors().isEmpty());
        assertEquals(1, log.getAllLoggingEvents().stream().filter(e -> e.getLevel() == uk.org.lidalia.slf4jext.Level.WARN).count());
    }
    @Test
    void theListenerIsAnExternalListenerSoClusterPeersReconcile() {
        DynamicScopeRegistrar scope = registrar("site_author", "/content/site");
        assertTrue(scope instanceof org.apache.sling.api.resource.observation.ExternalResourceChangeListener);
    }

    @Test
    void aSlowStaleCheckCannotUndoANewerRegistration() throws Exception {
        java.util.concurrent.CountDownLatch checking = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.CountDownLatch release = new java.util.concurrent.CountDownLatch(1);
        ResourceResolverFactory real = context.getService(ResourceResolverFactory.class);
        java.util.concurrent.atomic.AtomicBoolean first = new java.util.concurrent.atomic.AtomicBoolean(true);
        ResourceResolverFactory slowFirst = mock(ResourceResolverFactory.class);
        when(slowFirst.getServiceResourceResolver(any())).thenAnswer(call -> {
            if (first.getAndSet(false)) {
                // The activation check reads MISSING, then stalls before deciding.
                org.apache.sling.api.resource.ResourceResolver missing = mock(org.apache.sling.api.resource.ResourceResolver.class);
                checking.countDown();
                assertTrue(release.await(5, java.util.concurrent.TimeUnit.SECONDS));
                return missing;
            }
            return real.getServiceResourceResolver(call.getArgument(0));
        });
        DynamicOAuthScopeConfiguration config = mock(DynamicOAuthScopeConfiguration.class);
        when(config.scopeName()).thenReturn("late");
        when(config.resourcePath()).thenReturn("/content/late");
        when(config.requiredPrivileges()).thenReturn(new String[] {"jcr:read"});
        DynamicScopeRegistrar registrar = new DynamicScopeRegistrar();
        java.lang.reflect.Field f = DynamicScopeRegistrar.class.getDeclaredField("resolverFactory");
        f.setAccessible(true);
        f.set(registrar, slowFirst);

        Thread activation = new Thread(() -> registrar.activate(context.bundleContext(), config));
        activation.start();
        assertTrue(checking.await(5, java.util.concurrent.TimeUnit.SECONDS));
        path("/content/late");
        Thread listener = new Thread(() -> registrar.onChange(change(ResourceChange.ChangeType.ADDED, "/content/late")));
        listener.start();
        long deadline = System.currentTimeMillis() + 2000;
        while (listener.getState() != Thread.State.BLOCKED && listener.isAlive() && System.currentTimeMillis() < deadline) Thread.sleep(5);
        release.countDown();
        activation.join(5000);
        listener.join(5000);
        assertEquals(Collections.singletonList("late"), registeredNames(), "the newer PRESENT check must win");
    }
}
