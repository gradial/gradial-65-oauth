package com.gradial.core.oauth.obo;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.resource.ResourceResolver;
import org.osgi.service.cm.Configuration;
import org.osgi.service.cm.ConfigurationAdmin;
import org.osgi.service.cm.ConfigurationEvent;
import org.osgi.service.cm.ConfigurationListener;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;

/**
 * Detects AEM "Impersonate as" (Sling sudo). Delegation must act as, and be approved by, the person
 * who actually signed in, never by a session that is impersonating someone else.
 *
 * <p>The sudo cookie and parameter names come from SlingAuthenticator's configuration. They are read
 * once and re-read only when that configuration changes, never per request.
 */
@Component(service = {OboImpersonationGuard.class, ConfigurationListener.class})
public class OboImpersonationGuard implements ConfigurationListener {
    // Sling's SlingAuthenticator (auth.sudo.cookie / auth.sudo.parameter) can rename these.
    static final List<String> AUTHENTICATOR_PIDS = Collections.unmodifiableList(Arrays.asList(
            "org.apache.sling.engine.impl.auth.SlingAuthenticator",
            "org.apache.sling.auth.core.impl.SlingAuthenticator"));
    static final String DEFAULT_COOKIE = "sling.sudo";
    static final String DEFAULT_PARAMETER = "sudo";
    /** Resolver attribute that names the real user when a session was opened by impersonation. */
    static final String IMPERSONATOR_ATTRIBUTE = "user.impersonator";

    private volatile ConfigurationAdmin configurationAdmin;
    private volatile Names names = Names.defaults();

    @Reference(cardinality = ReferenceCardinality.OPTIONAL, policy = ReferencePolicy.DYNAMIC)
    void bindConfigurationAdmin(ConfigurationAdmin admin) {
        configurationAdmin = admin;
        reload();
    }

    void unbindConfigurationAdmin(ConfigurationAdmin admin) {
        if (configurationAdmin == admin) configurationAdmin = null;
    }

    @Activate
    void activate() { reload(); }

    @Override
    public void configurationEvent(ConfigurationEvent event) {
        if (AUTHENTICATOR_PIDS.contains(event.getPid())) reload();
    }

    /** True when the request carries any sudo selector, whether or not Sling would honor it. */
    boolean impersonationRequested(HttpServletRequest request) {
        Names current = names;
        for (String parameter : current.parameters) {
            if (request.getParameter(parameter) != null) return true;
        }
        Cookie[] sent = request.getCookies();
        if (sent != null) {
            for (Cookie cookie : sent) {
                if (current.cookies.contains(cookie.getName()) && cookie.getValue() != null && !cookie.getValue().isEmpty()) return true;
            }
        }
        return false;
    }

    /** True when a sudo selector is present or the resolved session reports an impersonator. */
    boolean impersonated(HttpServletRequest request) {
        if (impersonationRequested(request)) return true;
        if (request instanceof SlingHttpServletRequest) {
            ResourceResolver resolver = ((SlingHttpServletRequest) request).getResourceResolver();
            return resolver != null && resolver.getAttribute(IMPERSONATOR_ATTRIBUTE) != null;
        }
        return false;
    }

    void reload() {
        Names fresh = Names.defaults();
        ConfigurationAdmin admin = configurationAdmin;
        if (admin != null) {
            for (String pid : AUTHENTICATOR_PIDS) {
                try {
                    // listConfigurations never creates a configuration, unlike getConfiguration.
                    Configuration[] found = admin.listConfigurations("(service.pid=" + pid + ")");
                    if (found == null) continue;
                    for (Configuration configuration : found) {
                        if (configuration.getProperties() == null) continue;
                        addName(fresh.cookies, configuration.getProperties().get("auth.sudo.cookie"));
                        addName(fresh.parameters, configuration.getProperties().get("auth.sudo.parameter"));
                    }
                } catch (Exception e) {
                    // Defaults still apply; a configuration read failure must not open a gap.
                }
            }
        }
        names = fresh;
    }

    private static void addName(Set<String> names, Object value) {
        if (value instanceof String && !((String) value).isEmpty()) names.add((String) value);
    }

    /** Defaults are always included, so a renamed cookie never stops the stock one from being refused. */
    private static final class Names {
        final Set<String> cookies = new HashSet<>();
        final Set<String> parameters = new HashSet<>();

        static Names defaults() {
            Names names = new Names();
            names.cookies.add(DEFAULT_COOKIE);
            names.parameters.add(DEFAULT_PARAMETER);
            names.parameters.add(DEFAULT_COOKIE);
            return names;
        }
    }
}
