package com.gradial.core.oauth.obo;

import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;

@ObjectClassDefinition(name = "Gradial User Delegation (Author, opt-in)")
public @interface OboConfiguration {
    boolean enabled() default false;
    String clientId();
    @AttributeDefinition(description = "Hex SHA-256 of a random confidential-client secret of at least 32 random bytes; "
            + "never a user password. Changing it ends every existing grant")
    String clientSecretSha256();
    @AttributeDefinition(description = "Exact callback URLs Gradial may use. Changing them does not end existing grants")
    String[] redirectUris();
    @AttributeDefinition(description = "Trusted Author origin, HTTPS except localhost development")
    String publicOrigin();
    int accessTokenSeconds() default 300;
    @AttributeDefinition(description = "Absolute grant lifetime. Lowering it also shortens live grants; raising it never extends them")
    int grantSeconds() default 2592000;
    @AttributeDefinition(description = "Let `admin` and members of `administrators` connect. Delegation then grants them "
            + "full administrative access, so leave this off unless a deployment explicitly needs it")
    boolean allowAdministrators() default false;
}
