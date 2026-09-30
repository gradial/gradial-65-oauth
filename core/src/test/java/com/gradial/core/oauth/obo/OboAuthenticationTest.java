package com.gradial.core.oauth.obo;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.util.Base64;
import java.util.Collections;
import java.util.Set;

import javax.jcr.Credentials;
import javax.jcr.GuestCredentials;
import javax.jcr.RepositoryException;
import javax.jcr.SimpleCredentials;
import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.jackrabbit.oak.api.AuthInfo;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.junit.jupiter.api.Test;

class OboAuthenticationTest {
    private OboAuthenticationHandler handler(OboService service) throws Exception {
        OboAuthenticationHandler handler = new OboAuthenticationHandler();
        Field field = OboAuthenticationHandler.class.getDeclaredField("service");
        field.setAccessible(true);
        field.set(handler, service);
        return handler;
    }

    @Test
    void ordinaryBearerBasicAndCookieAuthenticationRemainAvailableToExistingHandlers() throws Exception {
        OboService service = mock(OboService.class);
        OboAuthenticationHandler handler = handler(service);
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRequestURI()).thenReturn("/content/site");
        for (String header : new String[] {null, "Bearer existing-granite-token", "Basic existing-user-credentials"}) {
            when(request.getHeader("Authorization")).thenReturn(header);
            assertNull(handler.extractCredentials(request, mock(HttpServletResponse.class)));
        }
        verifyNoInteractions(service);
    }

    @Test
    void invalidDelegationFailsRatherThanFallingBackToAValidBrowserCookie() throws Exception {
        OboService service = mock(OboService.class);
        when(service.authenticate("invalid")).thenThrow(OboService.invalid());
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader("Authorization")).thenReturn("GradialOBO invalid");
        assertSame(AuthenticationInfo.FAIL_AUTH, handler(service).extractCredentials(request, mock(HttpServletResponse.class)));
        verify(request).setAttribute("gradial.obo.failed", Boolean.TRUE);
    }

    @Test
    void repositoryOutageStopsProcessingWithoutFallingBackOrMisreportingAnInvalidUser() throws Exception {
        OboService service = mock(OboService.class);
        when(service.authenticate("token")).thenThrow(new RepositoryException("backend unavailable"));
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        when(request.getHeader("Authorization")).thenReturn("GradialOBO token");
        assertSame(AuthenticationInfo.DOING_AUTH, handler(service).extractCredentials(request, response));
        verify(response).setStatus(503);
    }

    @Test
    void authenticatedIdentityAndOpaqueCredentialsArePassedToOak() throws Exception {
        OboService service = mock(OboService.class);
        when(service.authenticate("opaque-access-token")).thenReturn("ordinary-author");
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader("Authorization")).thenReturn("GradialOBO opaque-access-token");
        AuthenticationInfo info = handler(service).extractCredentials(request, mock(HttpServletResponse.class));
        assertEquals("ordinary-author", info.getUser());
        assertInstanceOf(OboCredentials.class, info.get("user.jcr.credentials"));
        assertEquals("GradialOBO", info.getAuthType());
        assertNull(info.get("user.jcr.session"));
    }

    @Test
    void confidentialClientBasicCredentialsAreOnlyInterceptedAtTokenAndRevokeEndpoints() throws Exception {
        OboService service = mock(OboService.class);
        when(service.clientMatches("gradial", "secret")).thenReturn(true);
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader("Authorization")).thenReturn("Basic " + Base64.getEncoder()
                .encodeToString("gradial:secret".getBytes(StandardCharsets.UTF_8)));
        OboAuthenticationHandler handler = handler(service);
        for (String endpoint : new String[] {"/bin/gradial/obo/token", "/bin/gradial/obo/revoke"}) {
            when(request.getRequestURI()).thenReturn(endpoint);
            assertInstanceOf(GuestCredentials.class, handler.extractCredentials(request,
                    mock(HttpServletResponse.class)).get("user.jcr.credentials"));
        }
        when(request.getRequestURI()).thenReturn("/content/site");
        assertNull(handler.extractCredentials(request, mock(HttpServletResponse.class)));
    }

    @Test
    void competingClientAuthenticationMethodsAndDuplicateBodyParametersAreRejected() {
        OboService service = mock(OboService.class);
        when(service.clientMatches("gradial", "secret")).thenReturn(true);
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameterValues("client_id")).thenReturn(new String[] {"gradial", "other"});
        when(request.getParameterValues("client_secret")).thenReturn(new String[] {"secret"});
        assertFalse(OboClientAuthentication.accepts(request, service));
        when(request.getHeader("Authorization")).thenReturn("Basic !!!");
        assertFalse(OboClientAuthentication.accepts(request, service));
    }

    @Test
    void loginModuleUsesOriginalUserPrincipalsAndNeverServiceUserPrincipals() throws Exception {
        OboService service = mock(OboService.class);
        when(service.authenticate("token")).thenReturn("ordinary-author");
        Subject subject = new Subject();
        OboLoginModuleFactory.DelegationLoginModule module = module(service, new OboCredentials("token"));
        module.initialize(subject, null, Collections.emptyMap(), Collections.emptyMap());
        assertTrue(module.login());
        assertTrue(module.commit());
        AuthInfo info = subject.getPublicCredentials(AuthInfo.class).iterator().next();
        assertEquals("ordinary-author", info.getUserID());
        assertEquals(Collections.singleton("ordinary-author"), subject.getPrincipals().stream()
                .map(Principal::getName).collect(java.util.stream.Collectors.toSet()));
        assertTrue(module.logout());
        assertTrue(subject.getPrincipals().isEmpty());
        assertTrue(subject.getPublicCredentials().isEmpty());
    }

    @Test
    void loginModuleRejectsInvalidOpaqueCredentialsAndIgnoresOrdinaryCredentials() throws Exception {
        OboService service = mock(OboService.class);
        when(service.authenticate("bad")).thenThrow(new RepositoryException("failure"));
        OboLoginModuleFactory.DelegationLoginModule invalid = module(service, new OboCredentials("bad"));
        invalid.initialize(new Subject(), null, Collections.emptyMap(), Collections.emptyMap());
        assertThrows(LoginException.class, invalid::login);
        OboLoginModuleFactory.DelegationLoginModule ordinary = module(service, new SimpleCredentials("author", new char[0]));
        ordinary.initialize(new Subject(), null, Collections.emptyMap(), Collections.emptyMap());
        assertFalse(ordinary.login());
        assertFalse(ordinary.commit());
    }

    private OboLoginModuleFactory.DelegationLoginModule module(OboService service, Credentials credentials) {
        return new OboLoginModuleFactory.DelegationLoginModule(service) {
            @Override protected Credentials getCredentials() { return credentials; }
            @Override protected Set<? extends Principal> getPrincipals(String userId) {
                return Collections.singleton((Principal) () -> userId);
            }
        };
    }
}
