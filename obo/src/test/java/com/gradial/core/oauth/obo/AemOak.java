package com.gradial.core.oauth.obo;

import org.apache.jackrabbit.oak.security.internal.SecurityProviderBuilder;
import org.apache.jackrabbit.oak.spi.security.ConfigurationParameters;
import org.apache.jackrabbit.oak.spi.security.SecurityProvider;
import org.apache.jackrabbit.oak.spi.security.user.UserConfiguration;

/** Oak security configured with AEM's authorizable roots (/home/users, /home/groups). */
final class AemOak {
    private AemOak() { }

    static SecurityProvider security() {
        java.util.Map<String, Object> paths = new java.util.HashMap<>();
        paths.put("usersPath", "/home/users");
        paths.put("groupsPath", "/home/groups");
        paths.put("defaultDepth", 1);
        ConfigurationParameters user = ConfigurationParameters.of(paths);
        return SecurityProviderBuilder.newBuilder()
                .with(ConfigurationParameters.of(UserConfiguration.NAME, user)).build();
    }
}
