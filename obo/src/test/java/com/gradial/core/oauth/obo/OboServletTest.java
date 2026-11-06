package com.gradial.core.oauth.obo;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Field;

import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.resource.ResourceResolver;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

class OboServletTest {
    private OboServlet servlet(OboService service) throws Exception {
        OboServlet servlet = new OboServlet();
        Field field = OboServlet.class.getDeclaredField("service");
        field.setAccessible(true);
        field.set(servlet, service);
        return servlet;
    }

    private SlingHttpServletRequest consentRequest(String redirect) {
        SlingHttpServletRequest request = mock(SlingHttpServletRequest.class);
        ResourceResolver resolver = mock(ResourceResolver.class);
        when(request.getRequestURI()).thenReturn("/bin/gradial/obo/authorize");
        when(request.getResourceResolver()).thenReturn(resolver);
        when(resolver.getUserID()).thenReturn("writer");
        when(request.getParameterValues("response_type")).thenReturn(new String[] {"code"});
        when(request.getParameterValues("code_challenge_method")).thenReturn(new String[] {"S256"});
        when(request.getParameterValues("client_id")).thenReturn(new String[] {"client"});
        when(request.getParameterValues("redirect_uri")).thenReturn(new String[] {redirect});
        when(request.getParameterValues("code_challenge")).thenReturn(new String[] {"challenge"});
        when(request.getParameterValues("state")).thenReturn(new String[] {"state"});
        return request;
    }

    @Test
    void consentAllowsTheValidatedCallbackOriginWithoutExposingItsPathOrQuery() throws Exception {
        String redirect = "https://app.example.com:8443/callback;parameter?tenant=private";
        OboService service = mock(OboService.class);
        when(service.consent("writer", "client", redirect, "challenge", "state")).thenReturn("nonce");
        SlingHttpServletResponse response = mock(SlingHttpServletResponse.class);
        StringWriter html = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(html));

        servlet(service).doGet(consentRequest(redirect), response);

        verify(service).consent("writer", "client", redirect, "challenge", "state");
        ArgumentCaptor<String> policies = ArgumentCaptor.forClass(String.class);
        verify(response).setHeader(eq("Content-Security-Policy"), policies.capture());
        String policy = policies.getValue();
        assertTrue(policy.contains("form-action 'self' https://app.example.com:8443/;"));
        assertTrue(policy.contains("frame-ancestors 'none'; base-uri 'none'"));
        assertFalse(policy.contains("callback"));
        assertFalse(policy.contains("tenant"));
        ArgumentCaptor<String> referrers = ArgumentCaptor.forClass(String.class);
        verify(response, times(2)).setHeader(eq("Referrer-Policy"), referrers.capture());
        assertEquals("same-origin", referrers.getAllValues().get(1));
        verify(response).setHeader("Cache-Control", "no-store");
        assertTrue(html.toString().contains("name=':cq_csrf_token'"));
    }

    @Test
    void consentPageStylesWithANonceAndKeepsTheFormContract() throws Exception {
        OboService service = mock(OboService.class);
        when(service.consent(any(), any(), any(), any(), any())).thenReturn("form-nonce");
        SlingHttpServletResponse response = mock(SlingHttpServletResponse.class);
        StringWriter html = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(html));

        servlet(service).doGet(consentRequest("https://app.example.com/callback"), response);

        ArgumentCaptor<String> policies = ArgumentCaptor.forClass(String.class);
        verify(response).setHeader(eq("Content-Security-Policy"), policies.capture());
        String policy = policies.getValue();
        assertTrue(policy.startsWith("default-src 'none';"));
        assertFalse(policy.contains("unsafe-inline"));
        java.util.regex.Matcher style = java.util.regex.Pattern.compile("style-src 'nonce-([^']+)'").matcher(policy);
        assertTrue(style.find());
        String page = html.toString();
        assertTrue(page.contains("<style nonce='" + style.group(1) + "'>"));
        java.util.regex.Matcher script = java.util.regex.Pattern.compile("script-src 'nonce-([^']+)'").matcher(policy);
        assertTrue(script.find());
        assertTrue(page.contains("<script nonce='" + script.group(1) + "'>"));
        assertNotEquals(style.group(1), script.group(1));
        assertFalse(page.contains(" style="));
        assertTrue(page.contains("<form method=post action='/bin/gradial/obo/authorize'>"));
        assertTrue(page.contains("name=form_nonce value='form-nonce'"));
        assertTrue(page.contains("id=csrf type=hidden name=':cq_csrf_token'"));
        assertTrue(page.indexOf("name=approve value=yes disabled") < page.indexOf("name=approve value=no disabled"));
        assertTrue(page.contains("Connect Gradial as writer"));
        assertTrue(page.contains("Sign into AEM and try again."));
    }

    @Test
    void rejectedConsentKeepsNoReferrerAndNeverAllowsACallbackDestination() throws Exception {
        String redirect = "https://unregistered.example.com/callback";
        OboService service = mock(OboService.class);
        when(service.consent("writer", "client", redirect, "challenge", "state"))
                .thenThrow(OboService.invalid());
        SlingHttpServletResponse response = mock(SlingHttpServletResponse.class);
        when(response.getWriter()).thenReturn(new PrintWriter(new StringWriter()));

        servlet(service).doGet(consentRequest(redirect), response);

        verify(response).setStatus(400);
        verify(response).setHeader("Referrer-Policy", "no-referrer");
        verify(response, never()).setHeader(eq("Content-Security-Policy"), anyString());
        verify(response, never()).setHeader("Referrer-Policy", "same-origin");
    }
}
