package com.gradial.core.oauth.obo;

import static org.mockito.Mockito.*;

import java.lang.reflect.Field;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Cookie;

import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.resource.ResourceResolver;
import org.junit.jupiter.api.Test;

class OboAuthenticationFilterTest {
    private OboAuthenticationFilter filter(OboService service) throws Exception {
        OboAuthenticationFilter filter = new OboAuthenticationFilter();
        Field field = OboAuthenticationFilter.class.getDeclaredField("service");
        field.setAccessible(true);
        field.set(filter, service);
        return filter;
    }

    private SlingHttpServletRequest request(String header, String user) {
        SlingHttpServletRequest request = mock(SlingHttpServletRequest.class);
        ResourceResolver resolver = mock(ResourceResolver.class);
        when(request.getHeader("Authorization")).thenReturn(header);
        when(request.getResourceResolver()).thenReturn(resolver);
        when(resolver.getUserID()).thenReturn(user);
        when(request.getRemoteUser()).thenReturn(user);
        return request;
    }

    @Test
    void onlyTheValidatedDelegatedUserMayExecuteTheContentRequest() throws Exception {
        OboService service = mock(OboService.class);
        when(service.authenticate("valid")).thenReturn("writer");
        FilterChain chain = mock(FilterChain.class);
        SlingHttpServletRequest request = request("GradialOBO valid", "writer");
        HttpServletResponse response = mock(HttpServletResponse.class);
        filter(service).doFilter(request, response, chain);
        verify(chain).doFilter(request, response);
    }

    @Test
    void ambientAdminResolverOrRemoteUserCannotOverrideTheGrant() throws Exception {
        OboService service = mock(OboService.class);
        when(service.authenticate("valid")).thenReturn("writer");
        for (String selectedUser : new String[] {"admin", "writer"}) {
            SlingHttpServletRequest request = request("GradialOBO valid", selectedUser);
            when(request.getRemoteUser()).thenReturn("admin");
            HttpServletResponse response = mock(HttpServletResponse.class);
            FilterChain chain = mock(FilterChain.class);
            filter(service).doFilter(request, response, chain);
            verify(response).setStatus(403);
            verify(response).flushBuffer();
            verifyNoInteractions(chain);
        }
    }

    @Test
    void invalidGrantAndMissingServiceRefuseEvenAnAlreadyAuthenticatedAdmin() throws Exception {
        OboService service = mock(OboService.class);
        when(service.authenticate("invalid")).thenThrow(OboService.invalid());
        for (OboService available : new OboService[] {service, null}) {
            HttpServletResponse response = mock(HttpServletResponse.class);
            FilterChain chain = mock(FilterChain.class);
            filter(available).doFilter(request("GradialOBO invalid", "admin"), response, chain);
            verify(response).setStatus(403);
            verifyNoInteractions(chain);
            verify(response, never()).setHeader(eq("WWW-Authenticate"), anyString());
        }
    }

    @Test
    void nativeAuthenticationWithoutDelegationIsUnchanged() throws Exception {
        OboService service = mock(OboService.class);
        for (String header : new String[] {null, "Bearer native", "Basic normal"}) {
            SlingHttpServletRequest request = request(header, "native-user");
            HttpServletResponse response = mock(HttpServletResponse.class);
            FilterChain chain = mock(FilterChain.class);
            filter(service).doFilter(request, response, chain);
            verify(chain).doFilter(request, response);
        }
        verifyNoInteractions(service);
    }

    @Test
    void delegatedRequestsRefuseExplicitSudoEvenWhenTheProviderIgnoresItsParameter() throws Exception {
        OboService service = mock(OboService.class);
        for (String parameter : new String[] {"sudo", "sling.sudo"}) {
            SlingHttpServletRequest request = request("GradialOBO valid", "writer");
            when(request.getParameter(parameter)).thenReturn("admin");
            FilterChain chain = mock(FilterChain.class);
            HttpServletResponse response = mock(HttpServletResponse.class);
            filter(service).doFilter(request, response, chain);
            verify(response).setStatus(403);
            verifyNoInteractions(chain);
        }
        SlingHttpServletRequest request = request("GradialOBO valid", "writer");
        when(request.getCookies()).thenReturn(new Cookie[] {new Cookie("sling.sudo", "admin")});
        HttpServletResponse response = mock(HttpServletResponse.class);
        filter(service).doFilter(request, response, mock(FilterChain.class));
        verify(response).setStatus(403);
        verifyNoInteractions(service);
    }
}
