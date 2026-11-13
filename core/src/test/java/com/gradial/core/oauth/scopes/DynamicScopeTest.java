package com.gradial.core.oauth.scopes;

import static org.junit.jupiter.api.Assertions.assertFalse;

import java.lang.reflect.Method;
import java.util.Arrays;

import org.junit.jupiter.api.Test;
import org.osgi.service.component.annotations.Modified;

import com.gradial.core.oauth.config.DynamicOAuthScopeConfiguration;
import com.gradial.core.oauth.scopes.impl.DynamicScopeRegistrar;

/**
 * Guards against re-introducing {@code @Modified} on {@link DynamicScopeRegistrar}, the component behind each DynamicScope configuration.
 *
 * <p>Adobe's OAuth2ResourceServerImpl keys its allowed-scope map by
 * {@link com.adobe.granite.oauth.server.Scope#getName()} at bind time. If a config change
 * were handled via {@code modified} instead of forcing SCR to deactivate/reactivate the
 * component, the resource server would keep the scope bound under its old name and reject
 * tokens issued for a renamed scope.
 */
class DynamicScopeTest {

    @Test
    void activateIsNotAlsoBoundToModified() throws NoSuchMethodException {
        Method activate = DynamicScopeRegistrar.class.getDeclaredMethod("activate", org.osgi.framework.BundleContext.class, DynamicOAuthScopeConfiguration.class);

        assertFalse(activate.isAnnotationPresent(Modified.class),
                "activate() must not be @Modified: a config change has to re-register the service "
                        + "(deactivate+activate) so OAuth2ResourceServerImpl's bindScope/unbindScope "
                        + "keys the scope by its current name, not a stale one");
    }

    @Test
    void noMethodOnDynamicScopeIsAnnotatedModified() {
        boolean anyModified = Arrays.stream(DynamicScopeRegistrar.class.getDeclaredMethods())
                .anyMatch(method -> method.isAnnotationPresent(Modified.class));

        assertFalse(anyModified,
                "DynamicScope must have no @Modified method so config edits go through a full "
                        + "SCR re-registration instead of an in-place update");
    }
}
