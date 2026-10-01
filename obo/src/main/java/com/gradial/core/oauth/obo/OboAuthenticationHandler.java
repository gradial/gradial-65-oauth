package com.gradial.core.oauth.obo;

import java.io.IOException;

import javax.jcr.RepositoryException;
import javax.jcr.GuestCredentials;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.sling.auth.core.spi.AuthenticationHandler;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;

@Component(service = AuthenticationHandler.class,
        property = {"path=/", "service.ranking:Integer=10000", "authtype=GradialOBO"})
public class OboAuthenticationHandler implements AuthenticationHandler {
    @Reference
    private OboService service;

    @Override
    public AuthenticationInfo extractCredentials(HttpServletRequest request, HttpServletResponse response) {
        String authorization = request.getHeader("Authorization");
        String path = request.getRequestURI();
        if (("/bin/gradial/obo/token".equals(path) || "/bin/gradial/obo/revoke".equals(path))
                && authorization != null && authorization.startsWith("Basic ")) {
            if (!OboClientAuthentication.accepts(request, service)) {
                request.setAttribute("gradial.obo.failed", Boolean.TRUE);
                return AuthenticationInfo.FAIL_AUTH;
            }
            // OAuth client credentials are not an AEM user's Basic credentials.
            AuthenticationInfo info = new AuthenticationInfo("GradialClient");
            info.put("user.jcr.credentials", new GuestCredentials());
            return info;
        }
        if (authorization == null || !authorization.regionMatches(true, 0, OboService.SCHEME + " ", 0, 11)) return null;
        try {
            String token = authorization.substring(11);
            String userId = service.authenticate(token);
            AuthenticationInfo info = new AuthenticationInfo(OboService.SCHEME, userId);
            info.put("user.jcr.credentials", new OboCredentials(token));
            return info;
        } catch (OboService.InvalidDelegationException e) {
            request.setAttribute("gradial.obo.failed", Boolean.TRUE);
            return AuthenticationInfo.FAIL_AUTH;
        } catch (RepositoryException e) {
            response.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
            response.setHeader("Cache-Control", "no-store");
            return AuthenticationInfo.DOING_AUTH;
        }
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
}
