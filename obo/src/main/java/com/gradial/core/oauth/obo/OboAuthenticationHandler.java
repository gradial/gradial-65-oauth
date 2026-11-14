package com.gradial.core.oauth.obo;

import java.io.IOException;

import javax.jcr.GuestCredentials;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.sling.api.SlingException;
import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.auth.core.AuthenticationSupport;
import org.apache.sling.auth.core.spi.AuthenticationFeedbackHandler;
import org.apache.sling.auth.core.spi.AuthenticationHandler;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;

/**
 * Extracts {@code Authorization: GradialOBO <token>} into {@link OboCredentials} for the login module,
 * which is the only validator. Inert for every other request. It refuses denied paths here because
 * this runs for non-Sling contexts too (web console, Granite OAuth servlet context).
 */
@Component(service = AuthenticationHandler.class,
        property = {"path=/", "service.ranking:Integer=10000", "authtype=GradialOBO"})
public class OboAuthenticationHandler implements AuthenticationHandler, AuthenticationFeedbackHandler {
    static final String TOKEN_PATH = "/bin/gradial/obo/token";
    static final String REVOKE_PATH = "/bin/gradial/obo/revoke";
    private static final String FAILED = "gradial.obo.failed";

    @Reference(cardinality = ReferenceCardinality.OPTIONAL, policy = ReferencePolicy.DYNAMIC)
    private volatile OboService service;

    @Override
    public AuthenticationInfo extractCredentials(HttpServletRequest request, HttpServletResponse response) {
        String authorization = request.getHeader("Authorization");
        OboService current = service;
        if (clientEndpoint(request) && isBasic(authorization)) {
            if (current == null) {
                unavailable(response);
                return AuthenticationInfo.DOING_AUTH;
            }
            if (!OboClientAuthentication.accepts(request, current)) {
                request.setAttribute(FAILED, Boolean.TRUE);
                return AuthenticationInfo.FAIL_AUTH;
            }
            // OAuth client credentials are not an AEM user's Basic credentials.
            AuthenticationInfo info = new AuthenticationInfo("GradialClient");
            info.put("user.jcr.credentials", new GuestCredentials());
            return info;
        }
        if (!isDelegationHeader(authorization)) return null;
        String token = token(authorization);
        if (current == null || token.isEmpty()) {
            denyDelegation(response);
            return AuthenticationInfo.DOING_AUTH;
        }
        if (OboPaths.refuses(request.getMethod(), request.getRequestURI())) {
            OboAudit.event("path_refused", null, null, "method=" + request.getMethod() + " path=" + request.getRequestURI());
            denyDelegation(response);
            return AuthenticationInfo.DOING_AUTH;
        }
        AuthenticationInfo info = new AuthenticationInfo(OboService.SCHEME);
        info.put("user.jcr.credentials", new OboCredentials(token));
        return info;
    }

    static boolean isDelegationHeader(String authorization) {
        return authorization != null && authorization.regionMatches(true, 0, OboService.SCHEME, 0, 10)
                && (authorization.length() == 10 || Character.isWhitespace(authorization.charAt(10)));
    }

    /** The credential after the scheme; empty when there is none. */
    static String token(String authorization) {
        return authorization.length() <= 10 ? "" : authorization.substring(10).trim();
    }

    /** RFC 7617: the scheme name is case-insensitive. */
    static boolean isBasic(String authorization) {
        return authorization != null && authorization.regionMatches(true, 0, "Basic ", 0, 6);
    }

    static boolean clientEndpoint(HttpServletRequest request) {
        String path = OboPaths.normalize(request.getRequestURI());
        return TOKEN_PATH.equals(path) || REVOKE_PATH.equals(path);
    }

    @Override
    public boolean requestCredentials(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (!Boolean.TRUE.equals(request.getAttribute(FAILED))) return false;
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setHeader("WWW-Authenticate", "Basic realm=\"Gradial OBO\"");
        response.setHeader("Cache-Control", "no-store");
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write("{\"error\":\"invalid_client\"}");
        return true;
    }

    @Override
    public void dropCredentials(HttpServletRequest request, HttpServletResponse response) {
        // Disconnect is explicit at /revoke; a browser logout must not clear unrelated AEM cookies.
    }

    @Override
    public void authenticationFailed(HttpServletRequest request, HttpServletResponse response, AuthenticationInfo info) {
        if (OboService.SCHEME.equals(info.getAuthType())) denyDelegation(response);
    }

    @Override
    public boolean authenticationSucceeded(HttpServletRequest request, HttpServletResponse response, AuthenticationInfo info) {
        if (!OboService.SCHEME.equals(info.getAuthType())) return false;
        Object resolver = request.getAttribute(AuthenticationSupport.REQUEST_ATTRIBUTE_RESOLVER);
        if (!(resolver instanceof ResourceResolver) || !openedBy((ResourceResolver) resolver, request.getHeader("Authorization"))) {
            denyDelegation(response);
            return true;
        }
        response.setHeader("Cache-Control", "no-store");
        return false;
    }

    /** True only when the delegation login module opened this session with exactly this request's credential. */
    static boolean openedBy(ResourceResolver resolver, String authorization) {
        if (resolver == null || !isDelegationHeader(authorization)) return false;
        Object stamped = resolver.getAttribute(OboLoginModuleFactory.ACCESS_ATTRIBUTE);
        String token = token(authorization);
        return stamped instanceof String && !token.isEmpty() && OboService.equal((String) stamped, OboService.hash(token));
    }

    private static void unavailable(HttpServletResponse response) {
        response.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
        response.setHeader("Cache-Control", "no-store");
    }

    private static void denyDelegation(HttpServletResponse response) {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setHeader("Cache-Control", "no-store");
        try {
            // Commit now, so Sling cannot follow a failed delegation with a Basic or login-page challenge.
            response.flushBuffer();
        } catch (IOException e) {
            throw new SlingException("Cannot complete delegated authentication response", e);
        }
    }
}
