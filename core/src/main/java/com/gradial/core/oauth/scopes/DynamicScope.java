package com.gradial.core.oauth.scopes;

import java.util.Arrays;
import java.util.Objects;

import javax.servlet.http.HttpServletRequest;

import org.apache.jackrabbit.api.security.user.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.adobe.granite.oauth.server.ScopeWithPrivileges;
import com.gradial.core.oauth.config.DynamicOAuthScopeConfiguration;

/**
 * An OAuth scope defined by a {@code com.gradial.core.oauth.scopes.DynamicScope} factory configuration.
 *
 * <p>Instances are created and registered with Granite by
 * {@link com.gradial.core.oauth.scopes.impl.DynamicScopeRegistrar}, which registers a scope only while
 * its resource path exists and its name is not held by another scope.
 */
public class DynamicScope implements ScopeWithPrivileges {

    private static final Logger LOGGER = LoggerFactory.getLogger(DynamicScope.class);
    private static final String DEFAULT_ENDPOINT = "/oauth/token";
    private static final String DESCRIPTION_PREFIX = "Dynamic OAuth Configuration for ";

    private DynamicOAuthScopeConfiguration config;

    /**
     * Binds this scope to its configuration.
     *
     * @param config The OSGi configuration for this scope
     */
    protected void activate(DynamicOAuthScopeConfiguration config) {
        this.config = config;
        LOGGER.info("Activated dynamic OAuth scope: {}", config.scopeName());
        LOGGER.info("Resource path: {}", config.resourcePath());
        LOGGER.info("Required privileges: {}", Arrays.toString(config.requiredPrivileges()));
    }

    @Override
    public String[] getPrivileges() {
        return Objects.requireNonNull(config.requiredPrivileges(), "Required privileges cannot be empty");
    }

    @Override
    public String getName() {
        return Objects.requireNonNull(config.scopeName(), "Scope name cannot be empty");
    }

    @Override
    public String getResourcePath(User user) {
        return Objects.requireNonNull(config.resourcePath(), "Resource path cannot be empty");
    }

    @Override
    public String getEndpoint() {
        return DEFAULT_ENDPOINT;
    }

    @Override
    public String getDescription(HttpServletRequest httpServletRequest) {
        return DESCRIPTION_PREFIX + config.scopeName();
    }
}
