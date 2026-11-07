package com.gradial.core.oauth.obo;

import java.util.HashSet;
import java.util.Set;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.resource.ResourceResolver;
import org.osgi.framework.InvalidSyntaxException;
import org.osgi.service.cm.Configuration;
import org.osgi.service.cm.ConfigurationAdmin;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;

/**
 * Detects AEM "Impersonate as" (Sling sudo). Delegation must act as, and be approved by, the person
 * who actually signed in, never by a session that is impersonating someone else.
 */
@Component(service = OboImpersonationGuard.class)
public class OboImpersonationGuard {
    // Sling's SlingAuthenticator (auth.sudo.cookie / auth.sudo.parameter) can rename these.
    private static final String[] AUTHENTICATOR_PIDS = {
        "org.apache.sling.engine.impl.auth.SlingAuthenticator",
        "org.apache.sling.auth.core.impl.SlingAuthenticator"
    };
    static final String DEFAULT_COOKIE = "sling.sudo";
    static final String DEFAULT_PARAMETER = "sudo";
    /** Resolver attribute that names the real user when a session was opened by impersonation. */
    static final String IMPERSONATOR_ATTRIBUTE = "user.impersonator";

    @Reference(cardinality = ReferenceCardinality.OPTIONAL, policy = ReferencePolicy.DYNAMIC)
    private volatile ConfigurationAdmin configurationAdmin;

    /** True when the request carries any sudo selector, whether or not Sling would honor it. */
    boolean impersonationRequested(HttpServletRequest request) {
        Set<String> cookies = new HashSet<>();
        Set<String> parameters = new HashSet<>();
        cookies.add(DEFAULT_COOKIE);
        parameters.add(DEFAULT_PARAMETER);
        parameters.add(DEFAULT_COOKIE);
        collectConfiguredNames(cookies, parameters);
        for (String parameter : parameters) {
            if (request.getParameter(parameter) != null) return true;
        }
        Cookie[] sent = request.getCookies();
        if (sent != null) {
            for (Cookie cookie : sent) {
                if (cookies.contains(cookie.getName()) && cookie.getValue() != null && !cookie.getValue().isEmpty()) return true;
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

    private void collectConfiguredNames(Set<String> cookies, Set<String> parameters) {
        ConfigurationAdmin admin = configurationAdmin;
        if (admin == null) return;
        for (String pid : AUTHENTICATOR_PIDS) {
            try {
                // listConfigurations never creates a configuration, unlike getConfiguration.
                Configuration[] found = admin.listConfigurations("(service.pid=" + pid + ")");
                if (found == null) continue;
                for (Configuration configuration : found) {
                    if (configuration.getProperties() == null) continue;
                    addName(cookies, configuration.getProperties().get("auth.sudo.cookie"));
                    addName(parameters, configuration.getProperties().get("auth.sudo.parameter"));
                }
            } catch (java.io.IOException | InvalidSyntaxException | RuntimeException e) {
                // Defaults above still apply; a configuration read failure must not open a gap.
            }
        }
    }

    private static void addName(Set<String> names, Object value) {
        if (value instanceof String && !((String) value).isEmpty()) names.add((String) value);
    }
}
