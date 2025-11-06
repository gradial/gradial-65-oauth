package com.gradial.core.oauth.config;

import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;

/**
 * OSGi configuration interface for dynamic OAuth scope configuration.
 * Used to create factory configurations for OAuth scopes with different permissions.
 */
@ObjectClassDefinition(
        name = "Dynamic OAuth Scope Configuration for Gradial",
        description = "Configures dynamic OAuth scopes with custom privileges and resource paths"
)
public @interface DynamicOAuthScopeConfiguration {

    /**
     * The name of the OAuth scope.
     * This will be used as the scope identifier in OAuth requests.
     *
     * @return The scope name
     */
    @AttributeDefinition(
            name = "Scope Name",
            description = "The name of this OAuth scope (used as scope identifier in OAuth requests)"
    )
    String scopeName();

    /**
     * The resource path for this OAuth scope.
     * Defines the content tree path this scope has access to.
     *
     * @return The resource path
     */
    @AttributeDefinition(
            name = "Resource Path",
            description = "The resource path in the repository that this OAuth scope grants access to"
    )
    String resourcePath();

    /**
     * The required JCR privileges for this OAuth scope.
     * Defines what operations can be performed on the content.
     *
     * @return Array of JCR privileges
     */
    @AttributeDefinition(
            name = "Required Privileges",
            description = "The JCR privileges this OAuth scope grants to clients"
    )
    String[] requiredPrivileges() default { "jcr:read" };
}
