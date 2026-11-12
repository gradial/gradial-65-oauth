package com.gradial.core.oauth.obo;

import static org.mockito.Mockito.*;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;

import javax.servlet.FilterChain;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.request.RequestPathInfo;
import org.apache.sling.api.resource.ResourceResolver;
import org.junit.jupiter.api.Test;

class OboAuthenticationFilterTest {
    private static final String TOKEN = "goa_0123456789abcdefABCDEFGHIJKLMNOPQRSTUVWXYZa.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq";

    private static OboService service() {
        return mock(OboService.class);
    }

    private OboAuthenticationFilter filter(OboService service) throws Exception {
        OboAuthenticationFilter filter = new OboAuthenticationFilter();
        Field field = OboAuthenticationFilter.class.getDeclaredField("service");
        field.setAccessible(true);
        field.set(filter, service);
        Field guard = OboAuthenticationFilter.class.getDeclaredField("guard");
        guard.setAccessible(true);
        OboImpersonationGuard impersonation = new OboImpersonationGuard();
        impersonation.activate();
        guard.set(filter, impersonation);
        return filter;
    }

    /** A request whose session the login module stamped (or not) with the hash of {@code stampedToken}. */
    private SlingHttpServletRequest request(String header, String user, String stampedToken, String method, String path) {
        SlingHttpServletRequest request = mock(SlingHttpServletRequest.class);
        ResourceResolver resolver = mock(ResourceResolver.class);
        RequestPathInfo info = mock(RequestPathInfo.class);
        when(request.getHeader("Authorization")).thenReturn(header);
        when(request.getResourceResolver()).thenReturn(resolver);
        when(request.getRequestPathInfo()).thenReturn(info);
        when(request.getMethod()).thenReturn(method);
        when(info.getResourcePath()).thenReturn(path);
        when(request.getRequestURI()).thenReturn(path);
        org.apache.sling.api.resource.Resource resource = mock(org.apache.sling.api.resource.Resource.class);
        when(resource.getPath()).thenReturn(path);
        when(request.getResource()).thenReturn(resource);
        when(resolver.getUserID()).thenReturn(user);
        when(request.getRemoteUser()).thenReturn(user);
        if (stampedToken != null) {
            when(resolver.getAttribute(OboLoginModuleFactory.ACCESS_ATTRIBUTE)).thenReturn(OboService.hash(stampedToken));
        }
        return request;
    }

    private SlingHttpServletRequest request(String header, String user, String stampedToken) {
        return request(header, user, stampedToken, "POST", "/content/site/en");
    }

    private java.io.StringWriter body;

    private HttpServletResponse response() {
        HttpServletResponse response = mock(HttpServletResponse.class);
        body = new java.io.StringWriter();
        try { when(response.getWriter()).thenReturn(new java.io.PrintWriter(body)); } catch (java.io.IOException e) { throw new AssertionError(e); }
        return response;
    }

    private static void refused(HttpServletResponse response, FilterChain chain) throws Exception {
        verify(response).setStatus(403);
        verify(response).flushBuffer();
        verifyNoInteractions(chain);
        verify(response, never()).setHeader(eq("WWW-Authenticate"), anyString());
    }

    @Test
    void aSessionOpenedByTheLoginModuleForThisCredentialProceedsWithoutARepositoryRead() throws Exception {
        OboService service = service();
        FilterChain chain = mock(FilterChain.class);
        SlingHttpServletRequest request = request("GradialOBO " + TOKEN, "writer", TOKEN);
        HttpServletResponse response = response();
        filter(service).doFilter(request, response, chain);
        verify(chain).doFilter(request, response);
        verify(service, never()).validateAccess(any(), any(), any());
    }

    @Test
    void aCookieOrOtherHandlerSessionCannotStandInForTheDelegatedOne() throws Exception {
        String other = TOKEN.replace('A', 'B');
        for (String stamped : new String[] {null, other}) {
            HttpServletResponse response = response();
            FilterChain chain = mock(FilterChain.class);
            filter(service()).doFilter(request("GradialOBO " + TOKEN, "admin", stamped), response, chain);
            refused(response, chain);
        }
    }

    @Test
    void aRemoteUserThatDisagreesWithTheSessionIsRefused() throws Exception {
        SlingHttpServletRequest request = request("GradialOBO " + TOKEN, "writer", TOKEN);
        when(request.getRemoteUser()).thenReturn("admin");
        HttpServletResponse response = response();
        FilterChain chain = mock(FilterChain.class);
        filter(service()).doFilter(request, response, chain);
        refused(response, chain);
    }

    @Test
    void aMissingServiceRefusesEvenAnAlreadyAuthenticatedSession() throws Exception {
        HttpServletResponse response = response();
        FilterChain chain = mock(FilterChain.class);
        filter(null).doFilter(request("GradialOBO " + TOKEN, "writer", TOKEN), response, chain);
        refused(response, chain);
    }

    @Test
    void nativeAuthenticationWithoutDelegationIsUnchanged() throws Exception {
        OboService service = service();
        for (String header : new String[] {null, "Bearer native", "Basic normal"}) {
            SlingHttpServletRequest request = request(header, "native-user", null, "POST", "/crx/packmgr/service.jsp");
            HttpServletResponse response = response();
            FilterChain chain = mock(FilterChain.class);
            filter(service).doFilter(request, response, chain);
            verify(chain).doFilter(request, response);
        }
        verifyNoInteractions(service);
    }

    @Test
    void delegatedRequestsRefuseExplicitSudo() throws Exception {
        for (String parameter : new String[] {"sudo", "sling.sudo"}) {
            SlingHttpServletRequest request = request("GradialOBO " + TOKEN, "writer", TOKEN);
            when(request.getParameter(parameter)).thenReturn("admin");
            FilterChain chain = mock(FilterChain.class);
            HttpServletResponse response = response();
            filter(service()).doFilter(request, response, chain);
            refused(response, chain);
        }
        SlingHttpServletRequest request = request("GradialOBO " + TOKEN, "writer", TOKEN);
        when(request.getCookies()).thenReturn(new Cookie[] {new Cookie("sling.sudo", "admin")});
        HttpServletResponse response = response();
        FilterChain chain = mock(FilterChain.class);
        filter(service()).doFilter(request, response, chain);
        refused(response, chain);
    }

    @Test
    void theFixedCredentialAndAdministrationEndpointsAreRefused() throws Exception {
        String[][] refused = {
            {"POST", "/bin/gradial/obo/token"}, {"POST", "/oauth/token"}, {"GET", "/libs/granite/oauth/content/clients.html"},
            {"POST", "/crx/packmgr/service.jsp"}, {"GET", "/crx/de/index.jsp"}, {"PROPFIND", "/crx/server/crx.default/jcr:root/content"},
            {"POST", "/libs/granite/security/post/authorizables"}, {"GET", "/libs/granite/security/content/useradmin.html"},
            {"POST", "/libs/granite/security/currentuser.json"}, {"GET", "/system/console/bundles.json"}};
        for (String[] call : refused) {
            HttpServletResponse response = response();
            FilterChain chain = mock(FilterChain.class);
            filter(service()).doFilter(request("GradialOBO " + TOKEN, "writer", TOKEN, call[0], call[1]), response, chain);
            refused(response, chain);
        }
    }

    @Test
    void aMappedUriThatResolvesToARefusedResourceIsRefused() throws Exception {
        SlingHttpServletRequest request = request("GradialOBO " + TOKEN, "writer", TOKEN, "POST", "/content/vanity");
        org.apache.sling.api.resource.Resource packmgr = mock(org.apache.sling.api.resource.Resource.class);
        when(packmgr.getPath()).thenReturn("/crx/packmgr/service");
        when(request.getResource()).thenReturn(packmgr);
        HttpServletResponse response = response();
        FilterChain chain = mock(FilterChain.class);
        filter(service()).doFilter(request, response, chain);
        refused(response, chain);
    }

    @Test
    void everythingElseIsLeftToTheUsersOwnAcls() throws Exception {
        String[][] allowed = {
            {"POST", "/content/site/en"}, {"GET", "/libs/granite/security/currentuser.json"},
            {"GET", "/libs/granite/security/whoami.json"}, {"HEAD", "/libs/granite/security/userinfo.json"},
            // Formerly in the configurable defaults; now governed only by the consenting user's ACLs.
            {"POST", "/home/users/a/author"}, {"GET", "/etc/packages/x.zip"}, {"POST", "/etc/cloudservices/x"},
            {"POST", "/bin/wcmcommand"}, {"POST", "/bin/replicate.json"}, {"GET", "/libs/granite/csrf/token.json"}};
        for (String[] call : allowed) {
            SlingHttpServletRequest request = request("GradialOBO " + TOKEN, "writer", TOKEN, call[0], call[1]);
            HttpServletResponse response = response();
            FilterChain chain = mock(FilterChain.class);
            filter(service()).doFilter(request, response, chain);
            verify(chain).doFilter(request, response);
        }
    }

    @Test
    void requestBodiesAndParametersAreNotInspected() throws Exception {
        SlingHttpServletRequest request = request("GradialOBO " + TOKEN, "writer", TOKEN, "POST", "/content/site/en");
        HttpServletResponse response = response();
        FilterChain chain = mock(FilterChain.class);
        filter(service()).doFilter(request, response, chain);
        verify(chain).doFilter(request, response);
        verify(request, never()).getRequestParameterMap();
        verify(request, never()).getParameterMap();
        // The impersonation guard reads only the sudo parameter names, to refuse explicit sudo.
        verify(request, never()).getParameter(argThat((String name) -> !"sudo".equals(name) && !"sling.sudo".equals(name)));
        verify(request, never()).getParameterValues(anyString());
    }
}
