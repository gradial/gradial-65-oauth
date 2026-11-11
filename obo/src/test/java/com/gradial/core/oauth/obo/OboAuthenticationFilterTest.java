package com.gradial.core.oauth.obo;

import static org.mockito.Mockito.*;

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
        OboService service = mock(OboService.class);
        when(service.paths()).thenReturn(OboPaths.of(null));
        return service;
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
        HttpServletResponse response = mock(HttpServletResponse.class);
        filter(service).doFilter(request, response, chain);
        verify(chain).doFilter(request, response);
        verify(service, never()).validateAccess(any(), any(), any());
    }

    @Test
    void aCookieOrOtherHandlerSessionCannotStandInForTheDelegatedOne() throws Exception {
        String other = TOKEN.replace('A', 'B');
        for (String stamped : new String[] {null, other}) {
            HttpServletResponse response = mock(HttpServletResponse.class);
            FilterChain chain = mock(FilterChain.class);
            filter(service()).doFilter(request("GradialOBO " + TOKEN, "admin", stamped), response, chain);
            refused(response, chain);
        }
    }

    @Test
    void aRemoteUserThatDisagreesWithTheSessionIsRefused() throws Exception {
        SlingHttpServletRequest request = request("GradialOBO " + TOKEN, "writer", TOKEN);
        when(request.getRemoteUser()).thenReturn("admin");
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);
        filter(service()).doFilter(request, response, chain);
        refused(response, chain);
    }

    @Test
    void aMissingServiceRefusesEvenAnAlreadyAuthenticatedSession() throws Exception {
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);
        filter(null).doFilter(request("GradialOBO " + TOKEN, "writer", TOKEN), response, chain);
        refused(response, chain);
    }

    @Test
    void nativeAuthenticationWithoutDelegationIsUnchanged() throws Exception {
        OboService service = service();
        for (String header : new String[] {null, "Bearer native", "Basic normal"}) {
            SlingHttpServletRequest request = request(header, "native-user", null, "POST", "/crx/packmgr/service.jsp");
            HttpServletResponse response = mock(HttpServletResponse.class);
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
            HttpServletResponse response = mock(HttpServletResponse.class);
            filter(service()).doFilter(request, response, chain);
            refused(response, chain);
        }
        SlingHttpServletRequest request = request("GradialOBO " + TOKEN, "writer", TOKEN);
        when(request.getCookies()).thenReturn(new Cookie[] {new Cookie("sling.sudo", "admin")});
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);
        filter(service()).doFilter(request, response, chain);
        refused(response, chain);
    }

    @Test
    void deniedResolvedResourcePathsAreRefusedAndContentPathsAreNot() throws Exception {
        String[][] refused = {
            {"POST", "/crx/packmgr/service.jsp"}, {"GET", "/libs/granite/security/content/useradmin"},
            {"POST", "/bin/gradial/obo/token"}, {"POST", "/oauth/token"}, {"GET", "/etc/packages/x.zip"},
            {"POST", "/home/users/a/author"}, {"POST", "/libs/granite/security/post/authorizables"}};
        for (String[] call : refused) {
            HttpServletResponse response = mock(HttpServletResponse.class);
            FilterChain chain = mock(FilterChain.class);
            filter(service()).doFilter(request("GradialOBO " + TOKEN, "writer", TOKEN, call[0], call[1]), response, chain);
            refused(response, chain);
        }
        String[][] allowed = {
            {"POST", "/content/site/en"}, {"GET", "/libs/granite/security/currentuser"}, {"GET", "/home/users/a/author"},
            {"POST", "/content/dam/site/asset.jpg"}, {"GET", "/libs/granite/csrf/token"}};
        for (String[] call : allowed) {
            SlingHttpServletRequest request = request("GradialOBO " + TOKEN, "writer", TOKEN, call[0], call[1]);
            HttpServletResponse response = mock(HttpServletResponse.class);
            FilterChain chain = mock(FilterChain.class);
            filter(service()).doFilter(request, response, chain);
            verify(chain).doFilter(request, response);
        }
    }
    /** A delegated POST to an allowed resource that carries these Sling POST parameters. */
    private SlingHttpServletRequest postWith(String resourcePath, String[][] parameters) {
        SlingHttpServletRequest request = request("GradialOBO " + TOKEN, "writer", TOKEN, "POST", resourcePath);
        org.apache.sling.api.resource.Resource resource = mock(org.apache.sling.api.resource.Resource.class);
        when(resource.getPath()).thenReturn(resourcePath);
        when(request.getResource()).thenReturn(resource);
        java.util.Map<String, org.apache.sling.api.request.RequestParameter[]> map = new java.util.LinkedHashMap<>();
        for (String[] p : parameters) {
            org.apache.sling.api.request.RequestParameter value = mock(org.apache.sling.api.request.RequestParameter.class);
            when(value.isFormField()).thenReturn(!"FILE".equals(p.length > 2 ? p[2] : ""));
            when(value.getString()).thenReturn(p[1]);
            map.put(p[0], new org.apache.sling.api.request.RequestParameter[] {value});
        }
        org.apache.sling.api.request.RequestParameterMap parameterMap = mock(org.apache.sling.api.request.RequestParameterMap.class);
        when(parameterMap.entrySet()).thenReturn(map.entrySet());
        when(request.getRequestParameterMap()).thenReturn(parameterMap);
        return request;
    }

    @Test
    void slingPostTargetsOutsideTheAddressedResourceAreCheckedToo() throws Exception {
        String[][][] bypasses = {
            {{":operation", "delete"}, {":applyTo", "/etc/cloudservices/customer"}},
            {{":operation", "delete"}, {":applyTo", "../../../etc/cloudservices/customer"}},
            {{":operation", "delete"}, {":applyTo", "/etc/cloudservices/*"}},
            {{":operation", "move"}, {":dest", "/etc/packages/x"}},
            {{":operation", "copy"}, {":dest", "../../../crx/x"}},
            {{"/etc/cloudservices/customer/prop", "value"}},
            {{"../../../home/users/a/author/profile/email", "x"}},
            {{"./imported@MoveFrom", "/etc/cloudservices/customer"}},
            {{"./copy@CopyFrom", "../../../etc/packages/x.zip"}}};
        for (String[][] parameters : bypasses) {
            HttpServletResponse response = mock(HttpServletResponse.class);
            FilterChain chain = mock(FilterChain.class);
            filter(service()).doFilter(postWith("/content/site/en", parameters), response, chain);
            refused(response, chain);
        }
    }

    @Test
    void ordinaryContentWritesWithPathValuesAndUploadsStillWork() throws Exception {
        String[][][] allowed = {
            {{"jcr:title", "Hello"}, {"fileReference", "/content/dam/site/image.jpg"}},
            {{"jcr:content/cq:cloudserviceconfigs", "/etc/cloudservices/launch/site"}},
            {{"path", "/etc/cloudservices/customer"}},
            {{"./jcr:content/jcr:title", "Hi"}, {":redirect", "/crx/should-not-matter"}},
            {{":operation", "delete"}, {":applyTo", "/content/site/en/old-page"}},
            {{"file", "/etc/packages/looks-like-a-path", "FILE"}}};
        for (String[][] parameters : allowed) {
            SlingHttpServletRequest request = postWith("/content/site/en", parameters);
            HttpServletResponse response = mock(HttpServletResponse.class);
            FilterChain chain = mock(FilterChain.class);
            filter(service()).doFilter(request, response, chain);
            verify(chain).doFilter(request, response);
        }
    }
}
