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
        for (String target : OboRequestTargets.of(slingRequest)) {
            if (current.paths().refuses(slingRequest.getMethod(), target)) {
                OboAudit.event("path_refused", slingRequest.getRemoteUser(), null,
                        "method=" + slingRequest.getMethod() + " path=" + target);
                refuse(httpResponse);
                return;
            }
        }
        httpResponse.setHeader("Cache-Control", "no-store");
        chain.doFilter(request, response);
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
