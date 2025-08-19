package com.gradial65.core.oauth.scopes;

import java.util.Arrays;
import java.util.Objects;

import javax.servlet.http.HttpServletRequest;

import org.apache.jackrabbit.api.security.user.User;
import org.osgi.service.cm.ConfigurationAdmin;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.ConfigurationPolicy;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.metatype.annotations.Designate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.adobe.granite.oauth.server.Scope;
import com.adobe.granite.oauth.server.ScopeWithPrivileges;
import com.gradial65.core.oauth.config.DynamicOAuthScopeConfiguration;

/**
 * Dynamic implementation of OAuth Scope that can be configured via OSGi configuration.
 * This allows for the creation of multiple scopes with different permissions through configuration.
 */
@Component(
        service = Scope.class,
        configurationPid = "com.gradial65.core.oauth.scopes.DynamicScope",
        configurationPolicy = ConfigurationPolicy.REQUIRE
)
@Designate(ocd = DynamicOAuthScopeConfiguration.class, factory = true)
public class DynamicScope implements ScopeWithPrivileges {

    private static final Logger LOGGER = LoggerFactory.getLogger(DynamicScope.class);
    private static final String DEFAULT_ENDPOINT = "/oauth/token";
    private static final String DESCRIPTION_PREFIX = "Dynamic OAuth Configuration for ";

    @Reference
    private ConfigurationAdmin configurationAdmin;

    private DynamicOAuthScopeConfiguration config;

    /**
     * Activates or modifies this component with the provided configuration.
     *
     * @param config The OSGi configuration for this scope
     */
    @Activate
    @Modified
    protected void activate(DynamicOAuthScopeConfiguration config) {
        this.config = config;
        LOGGER.error("Activated dynamic OAuth scope: {}", config.scopeName());
        LOGGER.error("Resource path: {}", config.resourcePath());
        LOGGER.error("Required privileges: {}", Arrays.toString(config.requiredPrivileges()));
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