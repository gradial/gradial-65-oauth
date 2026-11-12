package com.gradial.core.oauth.obo;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import javax.servlet.http.Cookie;

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
        Field guard = OboServlet.class.getDeclaredField("guard");
        guard.setAccessible(true);
        guard.set(servlet, new OboImpersonationGuard());
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
        when(service.enabled()).thenReturn(true);
        when(service.knownClient("client")).thenReturn(true);
        when(service.registeredRedirect(redirect)).thenReturn(true);
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
        when(service.enabled()).thenReturn(true);
        when(service.knownClient(any())).thenReturn(true);
        when(service.registeredRedirect(any())).thenReturn(true);
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
        when(service.enabled()).thenReturn(true);
        when(service.knownClient("client")).thenReturn(true);
        SlingHttpServletResponse response = mock(SlingHttpServletResponse.class);
        when(response.getWriter()).thenReturn(new PrintWriter(new StringWriter()));

        servlet(service).doGet(consentRequest(redirect), response);

        verify(response).setStatus(400);
        verify(response).setHeader("Referrer-Policy", "no-referrer");
        verify(response, never()).setHeader(eq("Content-Security-Policy"), anyString());
        verify(response, never()).setHeader("Referrer-Policy", "same-origin");
        verify(response, never()).setHeader(eq("Location"), anyString());
        verify(service, never()).consent(any(), any(), any(), any(), any());
    }

    private static final String ORIGIN = "https://author.example.com";

    private OboFixture fixture;
    private StringWriter body;

    private SlingHttpServletRequest post(String path, String user, Map<String, String> parameters) {
        SlingHttpServletRequest request = mock(SlingHttpServletRequest.class);
        ResourceResolver resolver = mock(ResourceResolver.class);
        when(request.getRequestURI()).thenReturn(path);
        when(request.getResourceResolver()).thenReturn(resolver);
        when(resolver.getUserID()).thenReturn(user);
        parameters.forEach((name, value) -> {
            when(request.getParameterValues(name)).thenReturn(new String[] {value});
            when(request.getParameter(name)).thenReturn(value);
        });
        return request;
    }

    private SlingHttpServletResponse response() throws Exception {
        SlingHttpServletResponse response = mock(SlingHttpServletResponse.class);
        body = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(body));
        return response;
    }

    private static String basic(String id, String secret) {
        return "Basic " + Base64.getEncoder().encodeToString((id + ":" + secret).getBytes(StandardCharsets.UTF_8));
    }

    private OboService mockedService() {
        OboService service = mock(OboService.class);
        when(service.enabled()).thenReturn(true);
        when(service.origin()).thenReturn(ORIGIN);
        when(service.knownClient("client")).thenReturn(true);
        when(service.registeredRedirect("https://app.example.com/callback")).thenReturn(true);
        return service;
    }

    /** The error redirect a refusal sent to the registered callback. */
    private static java.net.URI errorRedirect(SlingHttpServletResponse response) {
        ArgumentCaptor<String> location = ArgumentCaptor.forClass(String.class);
        verify(response).setStatus(303);
        verify(response).setHeader(eq("Location"), location.capture());
        return java.net.URI.create(location.getValue());
    }

    private static Map<String, String> query(java.net.URI uri) {
        Map<String, String> out = new java.util.HashMap<>();
        for (String pair : uri.getRawQuery().split("&")) {
            String[] kv = pair.split("=", 2);
            try { out.put(kv[0], java.net.URLDecoder.decode(kv[1], "UTF-8")); } catch (Exception e) { throw new AssertionError(e); }
        }
        return out;
    }

    @Test
    void consentIsRefusedWhileAnotherUserIsBeingImpersonated() throws Exception {
        OboService service = mockedService();
        SlingHttpServletRequest sudoCookie = consentRequest("https://app.example.com/callback");
        when(sudoCookie.getCookies()).thenReturn(new Cookie[] {new Cookie("sling.sudo", "Ym9i")});
        SlingHttpServletRequest sudoParameter = consentRequest("https://app.example.com/callback");
        when(sudoParameter.getParameter("sudo")).thenReturn("bob");
        SlingHttpServletRequest impersonator = consentRequest("https://app.example.com/callback");
        when(impersonator.getResourceResolver().getAttribute("user.impersonator")).thenReturn("admin");
        for (SlingHttpServletRequest request : new SlingHttpServletRequest[] {sudoCookie, sudoParameter, impersonator}) {
            SlingHttpServletResponse response = response();
            servlet(service).doGet(request, response);
            Map<String, String> error = query(errorRedirect(response));
            assertEquals("access_denied", error.get("error"));
            assertTrue(error.get("error_description").contains("impersonating"));
            assertEquals("state", error.get("state"));
            assertFalse(error.containsKey("code"));
            verify(response, never()).setHeader(eq("Content-Security-Policy"), anyString());
        }
        verify(service, never()).consent(any(), any(), any(), any(), any());
    }

    @Test
    void approvalIsRefusedWhileAnotherUserIsBeingImpersonated() throws Exception {
        OboService service = mockedService();
        SlingHttpServletRequest request = post("/bin/gradial/obo/authorize", "bob", Map.of("approve", "yes", "form_nonce", "nonce"));
        when(request.getHeader("Origin")).thenReturn(ORIGIN);
        when(request.getCookies()).thenReturn(new Cookie[] {new Cookie("sling.sudo", "Ym9i")});
        SlingHttpServletResponse response = response();
        servlet(service).doPost(request, response);
        verify(response).setStatus(400);
        verify(service, never()).authorize(any(), any(), anyBoolean());
    }

    @Test
    void approvalRequiresTheExactTrustedOrigin() throws Exception {
        for (String origin : new String[] {null, "", "null", "https://evil.example", ORIGIN + "/", "http://author.example.com"}) {
            OboService service = mockedService();
            SlingHttpServletRequest request = post("/bin/gradial/obo/authorize", "writer", Map.of("approve", "yes", "form_nonce", "nonce"));
            when(request.getHeader("Origin")).thenReturn(origin);
            SlingHttpServletResponse response = response();
            servlet(service).doPost(request, response);
            verify(response).setStatus(400);
            verify(response, never()).setHeader(eq("Location"), anyString());
            verify(service, never()).authorize(any(), any(), anyBoolean());
        }
    }

    @Test
    void aDelegatedCredentialCannotConsentOrApprove() throws Exception {
        OboService service = mockedService();
        SlingHttpServletRequest get = consentRequest("https://app.example.com/callback");
        when(get.getAuthType()).thenReturn("GradialOBO");
        SlingHttpServletResponse getResponse = response();
        servlet(service).doGet(get, getResponse);
        assertEquals("access_denied", query(errorRedirect(getResponse)).get("error"));
        SlingHttpServletRequest post = post("/bin/gradial/obo/authorize", "writer", Map.of("approve", "yes", "form_nonce", "nonce"));
        when(post.getHeader("Origin")).thenReturn(ORIGIN);
        when(post.getAuthType()).thenReturn("GradialOBO");
        SlingHttpServletResponse postResponse = response();
        servlet(service).doPost(post, postResponse);
        verify(postResponse).setStatus(400);
        verify(service, never()).consent(any(), any(), any(), any(), any());
        verify(service, never()).authorize(any(), any(), anyBoolean());
    }

    @Test
    void tokenAndRevokeRefuseMissingWrongAndDelegatedClientAuthentication() throws Exception {
        for (String path : new String[] {"/bin/gradial/obo/token", "/bin/gradial/obo/revoke"}) {
            for (String authorization : new String[] {null, "GradialOBO go_anything", "Bearer abc", basic("gradial", "wrong"), "Basic !!!"}) {
                OboService service = mockedService();
                SlingHttpServletRequest request = post(path, "anonymous", Map.of("grant_type", "refresh_token",
                        "refresh_token", "x", "token", "x"));
                when(request.getHeader("Authorization")).thenReturn(authorization);
                SlingHttpServletResponse response = response();
                servlet(service).doPost(request, response);
                verify(response).setStatus(401);
                verify(response).setHeader("WWW-Authenticate", "Basic realm=\"Gradial OBO\"");
                assertTrue(body.toString().contains("invalid_client"));
                verify(service, never()).revoke(any());
                verify(service, never()).refresh(any());
                verify(service, never()).exchange(any(), any(), any());
            }
        }
    }

    @Test
    void clientCredentialsInTheBodyAreRefusedWhenTheyConflictWithBasic() throws Exception {
        OboService service = mockedService();
        when(service.clientMatches("gradial", "secret")).thenReturn(true);
        SlingHttpServletRequest request = post("/bin/gradial/obo/token", "anonymous", Map.of("grant_type", "refresh_token",
                "refresh_token", "x", "client_id", "gradial", "client_secret", "secret"));
        when(request.getHeader("Authorization")).thenReturn(basic("gradial", "secret"));
        SlingHttpServletResponse response = response();
        servlet(service).doPost(request, response);
        verify(response).setStatus(401);
        verify(service, never()).refresh(any());
    }

    @Test
    void aConsentNonceCannotBeApprovedByAnotherSignedInUser() throws Exception {
        fixture = new OboFixture();
        String nonce = fixture.service.consent(OboFixture.USER, OboFixture.CLIENT, OboFixture.REDIRECT,
                OboService.challenge(OboService.random()), OboFixture.STATE);
        Map<String, String> form = Map.of("approve", "yes", "form_nonce", nonce);
        SlingHttpServletRequest intruder = post("/bin/gradial/obo/authorize", "intruder", form);
        when(intruder.getHeader("Origin")).thenReturn(ORIGIN);
        SlingHttpServletResponse denied = response();
        servlet(fixture.service).doPost(intruder, denied);
        verify(denied).setStatus(400);
        verify(denied, never()).setHeader(eq("Location"), anyString());
        SlingHttpServletRequest owner = post("/bin/gradial/obo/authorize", OboFixture.USER, form);
        when(owner.getHeader("Origin")).thenReturn(ORIGIN);
        SlingHttpServletResponse approved = response();
        servlet(fixture.service).doPost(owner, approved);
        verify(approved).setStatus(303);
        ArgumentCaptor<String> location = ArgumentCaptor.forClass(String.class);
        verify(approved).setHeader(eq("Location"), location.capture());
        assertTrue(location.getValue().startsWith(OboFixture.REDIRECT + "?code=goc_"));
        assertTrue(location.getValue().endsWith("&state=" + OboFixture.STATE));
    }

    @Test
    void administratorsGetNoConsentPageAndNoNonce() throws Exception {
        fixture = new OboFixture();
        when(fixture.user.isAdmin()).thenReturn(true);
        SlingHttpServletRequest request = consentRequest(OboFixture.REDIRECT);
        when(request.getResourceResolver().getUserID()).thenReturn(OboFixture.USER);
        when(request.getParameterValues("client_id")).thenReturn(new String[] {OboFixture.CLIENT});
        when(request.getParameterValues("code_challenge")).thenReturn(new String[] {OboService.challenge(OboService.random())});
        when(request.getParameterValues("state")).thenReturn(new String[] {OboFixture.STATE});
        SlingHttpServletResponse response = response();
        servlet(fixture.service).doGet(request, response);
        java.net.URI callback = errorRedirect(response);
        assertTrue(callback.toString().startsWith(OboFixture.REDIRECT + "?"));
        Map<String, String> error = query(callback);
        assertEquals("access_denied", error.get("error"));
        assertEquals("administrators can't connect; sign in to AEM as your own user", error.get("error_description"));
        assertEquals(OboFixture.STATE, error.get("state"));
        assertFalse(body.toString().contains("form_nonce"));
        assertEquals(0, OboFixture.records(fixture.storage, OboService.CONSENTS, 2));
    }

    @Test
    void theTokenEndpointRejectsCredentialsOfTheWrongTypeAndStillServesTheRightOne() throws Exception {
        fixture = new OboFixture();
        String verifier = OboService.random();
        String nonce = fixture.service.consent(OboFixture.USER, OboFixture.CLIENT, OboFixture.REDIRECT,
                OboService.challenge(verifier), OboFixture.STATE);
        String code = fixture.service.authorize(nonce, OboFixture.USER, true).code;
        OboService.Tokens tokens = fixture.service.exchange(code, OboFixture.REDIRECT, verifier);
        String auth = basic(OboFixture.CLIENT, OboFixture.SECRET);
        for (Map<String, String> form : new Map[] {
                Map.of("grant_type", "refresh_token", "refresh_token", tokens.access),
                Map.of("grant_type", "authorization_code", "code", tokens.access, "redirect_uri", OboFixture.REDIRECT, "code_verifier", verifier),
                Map.of("grant_type", "authorization_code", "code", tokens.refresh, "redirect_uri", OboFixture.REDIRECT, "code_verifier", verifier),
                Map.of("grant_type", "authorization_code", "code", code, "redirect_uri", OboFixture.REDIRECT, "code_verifier", verifier)}) {
            SlingHttpServletRequest request = post("/bin/gradial/obo/token", "anonymous", form);
            when(request.getHeader("Authorization")).thenReturn(auth);
            SlingHttpServletResponse response = response();
            servlet(fixture.service).doPost(request, response);
            verify(response).setStatus(400);
            assertTrue(body.toString().contains("invalid_grant"));
        }
    }

    @Test
    void theTokenEndpointRefreshesWithTheRightCredential() throws Exception {
        fixture = new OboFixture();
        String verifier = OboService.random();
        String nonce = fixture.service.consent(OboFixture.USER, OboFixture.CLIENT, OboFixture.REDIRECT,
                OboService.challenge(verifier), OboFixture.STATE);
        OboService.Tokens tokens = fixture.service.exchange(
                fixture.service.authorize(nonce, OboFixture.USER, true).code, OboFixture.REDIRECT, verifier);
        SlingHttpServletRequest request = post("/bin/gradial/obo/token", "anonymous",
                Map.of("grant_type", "refresh_token", "refresh_token", tokens.refresh));
        when(request.getHeader("Authorization")).thenReturn(basic(OboFixture.CLIENT, OboFixture.SECRET));
        SlingHttpServletResponse response = response();
        servlet(fixture.service).doPost(request, response);
        verify(response, never()).setStatus(400);
        assertTrue(body.toString().contains("\"token_type\":\"GradialOBO\""));
    }

    @Test
    void anUnknownClientOrUnregisteredCallbackStaysOnThePageWithADescription() throws Exception {
        OboService service = mockedService();
        SlingHttpServletRequest unknownClient = consentRequest("https://app.example.com/callback");
        when(unknownClient.getParameterValues("client_id")).thenReturn(new String[] {"someone-else"});
        SlingHttpServletRequest unregistered = consentRequest("https://evil.example/callback");
        String[][] cases = {{"client_id is not the one configured on this AEM"}, {"redirect_uri is not registered"}};
        SlingHttpServletRequest[] requests = {unknownClient, unregistered};
        for (int i = 0; i < requests.length; i++) {
            SlingHttpServletResponse response = response();
            servlet(service).doGet(requests[i], response);
            verify(response).setStatus(400);
            verify(response, never()).setHeader(eq("Location"), anyString());
            assertTrue(body.toString().contains("\"error\":\"invalid_request\""));
            assertTrue(body.toString().contains(cases[i][0]), body.toString());
        }
        verify(service, never()).consent(any(), any(), any(), any(), any());
    }

    @Test
    void protocolErrorsWithAKnownClientAndCallbackGoBackToTheCallback() throws Exception {
        fixture = new OboFixture();
        Object[][] cases = {
            {"response_type", "token", "unsupported_response_type", "response_type must be code"},
            {"code_challenge_method", "plain", "invalid_request", "PKCE S256 required"},
            {"code_challenge", "short", "invalid_request", "PKCE S256 required"},
            {"state", "short", "invalid_request", "state is missing or invalid"}};
        for (Object[] c : cases) {
            SlingHttpServletRequest request = consentRequest(OboFixture.REDIRECT);
            when(request.getResourceResolver().getUserID()).thenReturn(OboFixture.USER);
            when(request.getParameterValues("client_id")).thenReturn(new String[] {OboFixture.CLIENT});
            when(request.getParameterValues("code_challenge")).thenReturn(new String[] {OboService.challenge(OboService.random())});
            when(request.getParameterValues("state")).thenReturn(new String[] {OboFixture.STATE});
            when(request.getParameterValues((String) c[0])).thenReturn(new String[] {(String) c[1]});
            SlingHttpServletResponse response = response();
            servlet(fixture.service).doGet(request, response);
            Map<String, String> error = query(errorRedirect(response));
            assertEquals(c[2], error.get("error"), (String) c[0]);
            assertEquals(c[3], error.get("error_description"), (String) c[0]);
            assertFalse(error.containsKey("code"));
        }
        assertEquals(0, OboFixture.records(fixture.storage, OboService.CONSENTS, 2));
    }

    @Test
    void aMissingStateIsReportedAndNotEchoed() throws Exception {
        fixture = new OboFixture();
        SlingHttpServletRequest request = consentRequest(OboFixture.REDIRECT);
        when(request.getResourceResolver().getUserID()).thenReturn(OboFixture.USER);
        when(request.getParameterValues("client_id")).thenReturn(new String[] {OboFixture.CLIENT});
        when(request.getParameterValues("code_challenge")).thenReturn(new String[] {OboService.challenge(OboService.random())});
        when(request.getParameterValues("state")).thenReturn(null);
        SlingHttpServletResponse response = response();
        servlet(fixture.service).doGet(request, response);
        Map<String, String> error = query(errorRedirect(response));
        assertEquals("state is missing or invalid", error.get("error_description"));
        assertFalse(error.containsKey("state"));
    }

    @Test
    void anExpiredConsentPageStaysOnThePageWithSignInExpired() throws Exception {
        fixture = new OboFixture();
        SlingHttpServletRequest request = post("/bin/gradial/obo/authorize", OboFixture.USER,
                Map.of("approve", "yes", "form_nonce", "gon_" + OboService.recordId(OboFixture.USER) + "." + OboService.random()));
        when(request.getHeader("Origin")).thenReturn("https://author.example.com");
        SlingHttpServletResponse response = response();
        servlet(fixture.service).doPost(request, response);
        verify(response).setStatus(400);
        verify(response, never()).setHeader(eq("Location"), anyString());
        assertTrue(body.toString().contains("sign-in expired, start again"), body.toString());
    }

    @Test
    void decliningRedirectsAccessDeniedWithADescriptionAndState() throws Exception {
        fixture = new OboFixture();
        String nonce = fixture.service.consent(OboFixture.USER, OboFixture.CLIENT, OboFixture.REDIRECT,
                OboService.challenge(OboService.random()), OboFixture.STATE);
        SlingHttpServletRequest request = post("/bin/gradial/obo/authorize", OboFixture.USER, Map.of("approve", "no", "form_nonce", nonce));
        when(request.getHeader("Origin")).thenReturn("https://author.example.com");
        SlingHttpServletResponse response = response();
        servlet(fixture.service).doPost(request, response);
        Map<String, String> error = query(errorRedirect(response));
        assertEquals("access_denied", error.get("error"));
        assertEquals("the user declined the connection", error.get("error_description"));
        assertEquals(OboFixture.STATE, error.get("state"));
    }

    @Test
    void eachRefusalLogsOneWarningWithItsReason() throws Exception {
        uk.org.lidalia.slf4jtest.TestLogger log = uk.org.lidalia.slf4jtest.TestLoggerFactory.getTestLogger(OboServlet.class);
        log.clearAll();
        fixture = new OboFixture();
        when(fixture.user.isAdmin()).thenReturn(true);
        SlingHttpServletRequest request = consentRequest(OboFixture.REDIRECT);
        when(request.getResourceResolver().getUserID()).thenReturn(OboFixture.USER);
        when(request.getParameterValues("client_id")).thenReturn(new String[] {OboFixture.CLIENT});
        when(request.getParameterValues("code_challenge")).thenReturn(new String[] {OboService.challenge(OboService.random())});
        when(request.getParameterValues("state")).thenReturn(new String[] {OboFixture.STATE});
        servlet(fixture.service).doGet(request, response());
        java.util.List<uk.org.lidalia.slf4jtest.LoggingEvent> warnings = new java.util.ArrayList<>();
        for (uk.org.lidalia.slf4jtest.LoggingEvent e : log.getAllLoggingEvents()) if (e.getLevel() == uk.org.lidalia.slf4jext.Level.WARN) warnings.add(e);
        assertEquals(1, warnings.size());
        assertTrue(warnings.get(0).getArguments().contains("administrator"));
        assertFalse(warnings.get(0).getArguments().toString().contains(OboFixture.STATE), "the state is not logged");
    }
    @Test
    void missingOrRepeatedTokenParametersAreInvalidRequestNotInvalidGrant() throws Exception {
        fixture = new OboFixture();
        String auth = basic(OboFixture.CLIENT, OboFixture.SECRET);
        Map<String, String>[] bodies = new Map[] {Map.of(), Map.of("grant_type", "refresh_token")};
        for (Map<String, String> parameters : bodies) {
            SlingHttpServletRequest request = post("/bin/gradial/obo/token", "anonymous", parameters);
            when(request.getHeader("Authorization")).thenReturn(auth);
            SlingHttpServletResponse response = response();
            servlet(fixture.service).doPost(request, response);
            verify(response).setStatus(400);
            assertTrue(body.toString().contains("\"invalid_request\""), body.toString());
        }
        SlingHttpServletRequest repeated = post("/bin/gradial/obo/token", "anonymous", Map.of("grant_type", "refresh_token"));
        when(repeated.getHeader("Authorization")).thenReturn(auth);
        when(repeated.getParameterValues("refresh_token")).thenReturn(new String[] {"a", "b"});
        SlingHttpServletResponse response = response();
        servlet(fixture.service).doPost(repeated, response);
        assertTrue(body.toString().contains("\"invalid_request\""), body.toString());
        SlingHttpServletRequest unknownGrant = post("/bin/gradial/obo/token", "anonymous", Map.of("grant_type", "password"));
        when(unknownGrant.getHeader("Authorization")).thenReturn(auth);
        response = response();
        servlet(fixture.service).doPost(unknownGrant, response);
        assertTrue(body.toString().contains("\"unsupported_grant_type\""), body.toString());
        SlingHttpServletRequest badRefresh = post("/bin/gradial/obo/token", "anonymous",
                Map.of("grant_type", "refresh_token", "refresh_token", "gor_" + OboService.recordId(OboFixture.USER) + "." + OboService.random()));
        when(badRefresh.getHeader("Authorization")).thenReturn(auth);
        response = response();
        servlet(fixture.service).doPost(badRefresh, response);
        assertTrue(body.toString().contains("\"invalid_grant\""), body.toString());
    }

    @Test
    void aMissingOrRepeatedResponseTypeIsInvalidRequest() throws Exception {
        fixture = new OboFixture();
        for (String[] responseType : new String[][] {null, {"code", "token"}}) {
            SlingHttpServletRequest request = consentRequest(OboFixture.REDIRECT);
            when(request.getResourceResolver().getUserID()).thenReturn(OboFixture.USER);
            when(request.getParameterValues("client_id")).thenReturn(new String[] {OboFixture.CLIENT});
            when(request.getParameterValues("code_challenge")).thenReturn(new String[] {OboService.challenge(OboService.random())});
            when(request.getParameterValues("state")).thenReturn(new String[] {OboFixture.STATE});
            when(request.getParameterValues("response_type")).thenReturn(responseType);
            SlingHttpServletResponse response = response();
            servlet(fixture.service).doGet(request, response);
            assertEquals("invalid_request", query(errorRedirect(response)).get("error"));
        }
    }
    @Test
    void emptyRequiredOAuthParametersAreInvalidRequest() throws Exception {
        fixture = new OboFixture();
        String auth = basic(OboFixture.CLIENT, OboFixture.SECRET);
        for (Map<String, String> parameters : java.util.List.of(Map.of("grant_type", ""), Map.of("grant_type", "refresh_token", "refresh_token", ""),
                Map.of("grant_type", "authorization_code", "code", "", "redirect_uri", OboFixture.REDIRECT, "code_verifier", OboService.random() + OboService.random()))) {
            SlingHttpServletRequest request = post("/bin/gradial/obo/token", "anonymous", parameters);
            when(request.getHeader("Authorization")).thenReturn(auth);
            SlingHttpServletResponse response = response();
            servlet(fixture.service).doPost(request, response);
            verify(response).setStatus(400);
            assertTrue(body.toString().contains("\"invalid_request\""), parameters + " -> " + body);
        }
        SlingHttpServletRequest authorize = consentRequest(OboFixture.REDIRECT);
        when(authorize.getResourceResolver().getUserID()).thenReturn(OboFixture.USER);
        when(authorize.getParameterValues("client_id")).thenReturn(new String[] {OboFixture.CLIENT});
        when(authorize.getParameterValues("code_challenge")).thenReturn(new String[] {OboService.challenge(OboService.random())});
        when(authorize.getParameterValues("state")).thenReturn(new String[] {OboFixture.STATE});
        when(authorize.getParameterValues("response_type")).thenReturn(new String[] {""});
        SlingHttpServletResponse response = response();
        servlet(fixture.service).doGet(authorize, response);
        assertEquals("invalid_request", query(errorRedirect(response)).get("error"));
    }
}
