package com.gradial.core.oauth.obo;

import java.io.IOException;

import javax.jcr.RepositoryException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Cookie;

import org.apache.sling.api.SlingHttpServletRequest;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;

@Component(service = Filter.class,
        property = {"sling.filter.scope=REQUEST", "service.ranking:Integer=10000"})
public class OboAuthenticationFilter implements Filter {
    @Reference(cardinality = ReferenceCardinality.OPTIONAL, policy = ReferencePolicy.DYNAMIC)
    private volatile OboService service;

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
        try {
            OboService current = service;
            if (current == null || authorization.length() <= 11 || !(request instanceof SlingHttpServletRequest)
                    || hasImpersonation((HttpServletRequest) request)) {
                refuse(httpResponse, HttpServletResponse.SC_FORBIDDEN);
                return;
            }
            String userId = current.authenticate(authorization.substring(11));
            SlingHttpServletRequest slingRequest = (SlingHttpServletRequest) request;
            // Authentication metadata is not proof: cookie handlers can select another actual session.
            if (!userId.equals(slingRequest.getResourceResolver().getUserID())
                    || !userId.equals(slingRequest.getRemoteUser())) {
                refuse(httpResponse, HttpServletResponse.SC_FORBIDDEN);
                return;
            }
            httpResponse.setHeader("Cache-Control", "no-store");
            chain.doFilter(request, response);
        } catch (OboService.InvalidDelegationException e) {
            refuse(httpResponse, HttpServletResponse.SC_FORBIDDEN);
        } catch (RepositoryException e) {
            refuse(httpResponse, HttpServletResponse.SC_SERVICE_UNAVAILABLE);
        }
    }

    private static boolean hasImpersonation(HttpServletRequest request) {
        if (request.getParameter("sudo") != null || request.getParameter("sling.sudo") != null) return true;
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("sling.sudo".equals(cookie.getName()) && !cookie.getValue().isEmpty()) return true;
            }
        }
        return false;
    }

    private static void refuse(HttpServletResponse response, int status) throws IOException {
        response.setStatus(status);
        response.setHeader("Cache-Control", "no-store");
        response.flushBuffer();
    }

    @Override
    public void init(FilterConfig config) { }

    @Override
    public void destroy() { }
}
