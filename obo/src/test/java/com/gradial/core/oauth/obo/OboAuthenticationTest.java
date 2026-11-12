package com.gradial.core.oauth.obo;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.jcr.GuestCredentials;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.auth.core.AuthenticationSupport;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.junit.jupiter.api.Test;

class OboAuthenticationTest {
    private static final String TOKEN = "goa_0123456789abcdefABCDEFGHIJKLMNOPQRSTUVWXYZa.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq";

    private static OboService service() {
        OboService service = mock(OboService.class);
        return service;
    }

    private OboAuthenticationHandler handler(OboService service) throws Exception {
        OboAuthenticationHandler handler = new OboAuthenticationHandler();
        Field field = OboAuthenticationHandler.class.getDeclaredField("service");
        field.setAccessible(true);
        field.set(handler, service);
        return handler;
    }

    private static HttpServletRequest request(String header, String method, String uri) {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader("Authorization")).thenReturn(header);
        when(request.getMethod()).thenReturn(method);
        when(request.getRequestURI()).thenReturn(uri);
        return request;
    }

    @Test
    void ordinaryBearerBasicAndCookieAuthenticationRemainAvailableToExistingHandlers() throws Exception {
        OboService service = service();
        OboAuthenticationHandler handler = handler(service);
        for (String header : new String[] {null, "Bearer existing-granite-token", "Basic existing-user-credentials"}) {
            assertNull(handler.extractCredentials(request(header, "GET", "/content/site"), mock(HttpServletResponse.class)));
        }
        verifyNoInteractions(service);
    }

    @Test
    void theHandlerOnlyWrapsTheCredentialAndNeverReadsTheRepository() throws Exception {
        OboService service = service();
        AuthenticationInfo info = handler(service).extractCredentials(request("GradialOBO  " + TOKEN + " ", "POST", "/content/site"),
                mock(HttpServletResponse.class));
        assertEquals("GradialOBO", info.getAuthType());
        assertNull(info.getUser(), "identity comes from the login module, not from the header");
        assertEquals(TOKEN, ((OboCredentials) info.get("user.jcr.credentials")).token());
        verify(service, never()).validateAccess(any(), any(), any());
    }

    @Test
    void anEmptyCredentialOrAMissingServiceFailsWithoutFallingBack() throws Exception {
        for (OboService available : new OboService[] {null, service()}) {
            HttpServletResponse response = mock(HttpServletResponse.class);
            String header = available == null ? "GradialOBO " + TOKEN : "GradialOBO   ";
            assertSame(AuthenticationInfo.DOING_AUTH, handler(available).extractCredentials(request(header, "GET", "/content"), response));
            verify(response).setStatus(403);
            verify(response).flushBuffer();
            verify(response, never()).setHeader(eq("WWW-Authenticate"), anyString());
        }
    }

    @Test
    void fixedEndpointsAreRefusedBeforeLoginIncludingNonSlingContextsAndEncodedForms() throws Exception {
        String[] denied = {"/system/console/bundles", "/oauth/token", "/crx/de/index.jsp", "/crx/%70ackmgr/service.jsp",
            "//crx//packmgr", "/content/../crx/packmgr", "/LIBS/granite/security/post/authorizables", "/bin/gradial/obo/authorize",
            "/libs/granite/oauth/authorize", "/crx/server;x=y/crx.default", "/%2e%2e/crx", "/crx%00"};
        for (String uri : denied) {
            HttpServletResponse response = mock(HttpServletResponse.class);
            assertSame(AuthenticationInfo.DOING_AUTH, handler(service()).extractCredentials(
                    request("GradialOBO " + TOKEN, "GET", uri), response), uri);
            verify(response).setStatus(403);
        }
        for (String allowed : new String[] {"/libs/granite/security/currentuser.json", "/etc/packages/my.zip", "/content/site"}) {
            assertNotNull(handler(service()).extractCredentials(request("GradialOBO " + TOKEN, "GET", allowed),
                    mock(HttpServletResponse.class)).get("user.jcr.credentials"), allowed);
        }
    }

    @Test
    void failedRepositoryLoginCommitsDenialBeforeSlingCanRequestBasicCredentials() throws Exception {
        HttpServletResponse response = mock(HttpServletResponse.class);
        handler(service()).authenticationFailed(mock(HttpServletRequest.class), response, new AuthenticationInfo("GradialOBO"));
        verify(response).setStatus(403);
        verify(response).flushBuffer();
        verify(response, never()).setHeader(eq("WWW-Authenticate"), anyString());
    }

    @Test
    void successRequiresTheSessionTheLoginModuleOpenedForThisCredential() throws Exception {
        OboAuthenticationHandler handler = handler(service());
        HttpServletRequest request = request("GradialOBO " + TOKEN, "GET", "/content");
        ResourceResolver resolver = mock(ResourceResolver.class);
        when(request.getAttribute(AuthenticationSupport.REQUEST_ATTRIBUTE_RESOLVER)).thenReturn(resolver);
        HttpServletResponse response = mock(HttpServletResponse.class);
        assertTrue(handler.authenticationSucceeded(request, response, new AuthenticationInfo("GradialOBO")));
        verify(response).setStatus(403);
        when(resolver.getAttribute(OboLoginModuleFactory.ACCESS_ATTRIBUTE)).thenReturn(OboService.hash(TOKEN));
        assertFalse(handler.authenticationSucceeded(request, mock(HttpServletResponse.class), new AuthenticationInfo("GradialOBO")));
    }

    @Test
    void confidentialClientBasicCredentialsAreOnlyInterceptedAtTokenAndRevokeEndpoints() throws Exception {
        OboService service = service();
        when(service.clientMatches("gradial", "secret")).thenReturn(true);
        String basic = Base64.getEncoder().encodeToString("gradial:secret".getBytes(StandardCharsets.UTF_8));
        OboAuthenticationHandler handler = handler(service);
        for (String scheme : new String[] {"Basic ", "basic ", "BASIC "}) {
            for (String endpoint : new String[] {"/bin/gradial/obo/token", "/bin/gradial/obo/revoke", "/bin/gradial//obo/token"}) {
                assertInstanceOf(GuestCredentials.class, handler.extractCredentials(request(scheme + basic, "POST", endpoint),
                        mock(HttpServletResponse.class)).get("user.jcr.credentials"), scheme + endpoint);
            }
        }
        assertNull(handler.extractCredentials(request("Basic " + basic, "POST", "/content/site"), mock(HttpServletResponse.class)));
    }

    @Test
    void competingClientAuthenticationMethodsAndDuplicateBodyParametersAreRejected() {
        OboService service = service();
        when(service.clientMatches("gradial", "secret")).thenReturn(true);
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameterValues("client_id")).thenReturn(new String[] {"gradial", "other"});
        when(request.getParameterValues("client_secret")).thenReturn(new String[] {"secret"});
        assertFalse(OboClientAuthentication.accepts(request, service));
        when(request.getHeader("Authorization")).thenReturn("Basic !!!");
        assertFalse(OboClientAuthentication.accepts(request, service));
    }
}
