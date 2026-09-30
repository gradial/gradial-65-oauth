package com.gradial.core.oauth.obo;

import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;

@ObjectClassDefinition(name = "Gradial User Delegation (Author, opt-in)")
public @interface OboConfiguration {
    boolean enabled() default false;
    String clientId();
    @AttributeDefinition(description = "Hex SHA-256 of a random confidential-client secret; never a user password")
    String clientSecretSha256();
    String[] redirectUris();
    @AttributeDefinition(description = "Trusted Author origin, HTTPS except localhost development")
    String publicOrigin();
    int accessTokenSeconds() default 300;
    int grantSeconds() default 2592000;
}
