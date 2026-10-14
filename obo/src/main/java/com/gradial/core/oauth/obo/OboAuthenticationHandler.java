package com.gradial.core.oauth.obo;

import java.io.IOException;

import javax.jcr.RepositoryException;
import javax.jcr.GuestCredentials;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.sling.auth.core.spi.AuthenticationHandler;
import org.apache.sling.auth.core.spi.AuthenticationFeedbackHandler;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.auth.core.AuthenticationSupport;
import org.apache.sling.api.SlingException;
import org.apache.sling.api.resource.ResourceResolver;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;

@Component(service = AuthenticationHandler.class,
        property = {"path=/", "service.ranking:Integer=10000", "authtype=GradialOBO"})
public class OboAuthenticationHandler implements AuthenticationHandler, AuthenticationFeedbackHandler {
    @Reference(cardinality = ReferenceCardinality.OPTIONAL, policy = ReferencePolicy.DYNAMIC)
    private volatile OboService service;

    @Override
    public AuthenticationInfo extractCredentials(HttpServletRequest request, HttpServletResponse response) {
        String authorization = request.getHeader("Authorization");
        String path = request.getRequestURI();
        OboService current = service;
        if (("/bin/gradial/obo/token".equals(path) || "/bin/gradial/obo/revoke".equals(path))
                && authorization != null && authorization.startsWith("Basic ")) {
            if (current == null) {
                response.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
                response.setHeader("Cache-Control", "no-store");
                return AuthenticationInfo.DOING_AUTH;
            }
            if (!OboClientAuthentication.accepts(request, current)) {
                request.setAttribute("gradial.obo.failed", Boolean.TRUE);
                return AuthenticationInfo.FAIL_AUTH;
            }
            // OAuth client credentials are not an AEM user's Basic credentials.
            AuthenticationInfo info = new AuthenticationInfo("GradialClient");
            info.put("user.jcr.credentials", new GuestCredentials());
            return info;
        }
        if (!isDelegationHeader(authorization)) return null;
        if (current == null || authorization.length() <= 11) {
            denyDelegation(response);
            return AuthenticationInfo.DOING_AUTH;
        }
        try {
            String token = authorization.substring(11);
            String userId = current.authenticate(token);
            AuthenticationInfo info = new AuthenticationInfo(OboService.SCHEME, userId);
            info.put("user.jcr.credentials", new OboCredentials(token));
            return info;
        } catch (OboService.InvalidDelegationException e) {
            // FAIL_AUTH asks Sling to choose another login handler, which can challenge for Basic.
            denyDelegation(response);
            return AuthenticationInfo.DOING_AUTH;
        } catch (RepositoryException e) {
            response.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
            response.setHeader("Cache-Control", "no-store");
            return AuthenticationInfo.DOING_AUTH;
        }
    }

    static boolean isDelegationHeader(String authorization) {
        return authorization != null && authorization.regionMatches(true, 0, OboService.SCHEME, 0, 10)
                && (authorization.length() == 10 || Character.isWhitespace(authorization.charAt(10)));
    }

    @Override
    public boolean requestCredentials(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (!Boolean.TRUE.equals(request.getAttribute("gradial.obo.failed"))) return false;
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        boolean clientEndpoint = "/bin/gradial/obo/token".equals(request.getRequestURI())
                || "/bin/gradial/obo/revoke".equals(request.getRequestURI());
        response.setHeader("WWW-Authenticate", clientEndpoint ? "Basic realm=\"Gradial OBO\"" : OboService.SCHEME);
        response.setHeader("Cache-Control", "no-store");
        if (clientEndpoint) {
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write("{\"error\":\"invalid_client\"}");
        }
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
        if (!(resolver instanceof ResourceResolver) || !info.getUser().equals(((ResourceResolver) resolver).getUserID())) {
            denyDelegation(response);
            return true;
        }
        response.setHeader("Cache-Control", "no-store");
        return false;
    }

    private static void denyDelegation(HttpServletResponse response) {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setHeader("Cache-Control", "no-store");
        try {
            response.flushBuffer();
        } catch (IOException e) {
            throw new SlingException("Cannot complete delegated authentication response", e);
        }
    }
}
