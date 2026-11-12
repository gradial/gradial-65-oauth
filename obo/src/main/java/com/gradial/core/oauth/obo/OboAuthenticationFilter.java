package com.gradial.core.oauth.obo;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.sling.api.SlingHttpServletRequest;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;

/**
 * Last line for delegated Sling requests: the session must be the one the delegation login module
 * opened for this request's credential (a cookie handler or a sudo switch cannot substitute another),
 * and no path the request can act on (see {@link OboRequestTargets}) may be a denied surface. No
 * repository read.
 */
@Component(service = Filter.class,
        property = {"sling.filter.scope=REQUEST", "service.ranking:Integer=10000"})
public class OboAuthenticationFilter implements Filter {
    @Reference(cardinality = ReferenceCardinality.OPTIONAL, policy = ReferencePolicy.DYNAMIC)
    private volatile OboService service;
    @Reference
    private OboImpersonationGuard guard;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (!(request instanceof HttpServletRequest) || !(response instanceof HttpServletResponse)) {
            chain.doFilter(request, response);
            return;
        }
        String authorization = ((HttpServletRequest) request).getHeader("Authorization");
        if (!OboAuthenticationHandler.isDelegationHeader(authorization)) {
            chain.doFilter(request, response);
            return;
        }
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        OboService current = service;
        if (current == null || !(request instanceof SlingHttpServletRequest) || guard.impersonated((HttpServletRequest) request)) {
            refuse(httpResponse);
            return;
        }
        SlingHttpServletRequest slingRequest = (SlingHttpServletRequest) request;
        if (!OboAuthenticationHandler.openedBy(slingRequest.getResourceResolver(), authorization)
                || slingRequest.getRemoteUser() == null
                || !slingRequest.getRemoteUser().equals(slingRequest.getResourceResolver().getUserID())) {
            refuse(httpResponse);
            return;
        }
        String method = slingRequest.getMethod();
        try {
            for (OboRequestTargets.Target target : OboRequestTargets.of(slingRequest)) {
                if (current.paths().refusesRepositoryPath(method, target.path)) {
                    OboAudit.event("path_refused", slingRequest.getRemoteUser(), null,
                            "method=" + method + " parameter=" + target.parameter + " path=" + target.path);
                    refuseTarget(httpResponse, target.parameter + " targets a path that Gradial delegated sessions cannot change");
                    return;
                }
            }
        } catch (OboRequestTargets.UnprovableTarget e) {
            OboAudit.event("path_refused", slingRequest.getRemoteUser(), null,
                    "method=" + method + " parameter=" + e.parameter + " reason=unprovable_target");
            refuseTarget(httpResponse, e.getMessage());
            return;
        }
        httpResponse.setHeader("Cache-Control", "no-store");
        chain.doFilter(request, response);
    }

    /** 403 that names the parameter, so a client can tell a refused target from an AEM permission error. */
    private static void refuseTarget(HttpServletResponse response, String description) throws IOException {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setHeader("Cache-Control", "no-store");
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write("{\"error\":\"access_denied\",\"error_description\":\"" + json(description) + "\"}");
        response.flushBuffer();
    }

    private static String json(String value) {
        StringBuilder out = new StringBuilder(value.length());
        for (char c : value.toCharArray()) {
            if (c == '"' || c == '\\') out.append('\\').append(c);
            else if (c < 0x20) out.append(' ');
            else out.append(c);
        }
        return out.toString();
    }

    private static void refuse(HttpServletResponse response) throws IOException {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setHeader("Cache-Control", "no-store");
        response.flushBuffer();
    }

    @Override
    public void init(FilterConfig config) { }

    @Override
    public void destroy() { }
}
