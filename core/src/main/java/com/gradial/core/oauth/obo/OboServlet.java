package com.gradial.core.oauth.obo;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import javax.jcr.RepositoryException;
import javax.servlet.Servlet;

import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.servlets.SlingAllMethodsServlet;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;

@Component(service = Servlet.class, property = {
        "sling.servlet.paths=/bin/gradial/obo/authorize", "sling.servlet.paths=/bin/gradial/obo/token",
        "sling.servlet.paths=/bin/gradial/obo/revoke", "sling.servlet.paths.strict:Boolean=true",
        "sling.servlet.methods=GET", "sling.servlet.methods=POST",
        "sling.auth.requirements=+/bin/gradial/obo/authorize",
        "sling.auth.requirements=-/bin/gradial/obo/token", "sling.auth.requirements=-/bin/gradial/obo/revoke"})
public class OboServlet extends SlingAllMethodsServlet {
    private static final long serialVersionUID = 1L;
    @Reference
    private OboService service;

    @Override
    protected void doGet(SlingHttpServletRequest request, SlingHttpServletResponse response) throws IOException {
        headers(response);
        if (!request.getRequestURI().equals("/bin/gradial/obo/authorize")) { response.setStatus(405); return; }
        try {
            String user = browserUser(request);
            if (!"code".equals(parameter(request, "response_type"))
                    || !"S256".equals(parameter(request, "code_challenge_method"))) throw OboService.invalid();
            String nonce = service.consent(user, parameter(request, "client_id"), parameter(request, "redirect_uri"),
                    parameter(request, "code_challenge"), parameter(request, "state"));
            String scriptNonce = OboService.random();
            response.setHeader("Content-Security-Policy", "default-src 'none'; script-src 'nonce-" + scriptNonce
                    + "'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
            response.setContentType("text/html;charset=UTF-8");
            response.getWriter().write("<!doctype html><html><head><title>Connect Gradial</title></head><body>"
                    + "<h1>Connect Gradial as " + html(user) + "</h1>"
                    + "<p>Gradial will use your current AEM permissions. You can revoke this connection from Gradial.</p>"
                    + "<form method=post action='/bin/gradial/obo/authorize'><input type=hidden name=form_nonce value='"
                    + nonce + "'><input id=csrf type=hidden name=':cq_csrf_token'>"
                    + "<button disabled name=approve value=yes>Connect</button><button disabled name=approve value=no>Cancel</button>"
                    + "</form><p id=error></p><script nonce='" + scriptNonce + "'>"
                    + "fetch('/libs/granite/csrf/token.json',{credentials:'same-origin'}).then(r=>{if(!r.ok)throw Error();return r.json()})"
                    + ".then(t=>{if(!t.token)throw Error();document.getElementById('csrf').value=t.token;"
                    + "document.querySelectorAll('button').forEach(b=>b.disabled=false)})"
                    + ".catch(()=>document.getElementById('error').textContent='Sign into AEM and try again.');</script></body></html>");
        } catch (OboService.InvalidDelegationException | IllegalArgumentException e) { error(response, 400, "invalid_request"); }
        catch (RepositoryException e) { error(response, 503, "temporarily_unavailable"); }
    }

    @Override
    protected void doPost(SlingHttpServletRequest request, SlingHttpServletResponse response) throws IOException {
        headers(response);
        if (!service.enabled()) { error(response, 503, "temporarily_unavailable"); return; }
        String path = request.getRequestURI();
        try {
            if (path.equals("/bin/gradial/obo/authorize")) {
                String user = browserUser(request);
                if (!service.origin().equals(request.getHeader("Origin"))) throw OboService.invalid();
                String approval = parameter(request, "approve");
                if (!"yes".equals(approval) && !"no".equals(approval)) throw OboService.invalid();
                OboService.Authorization authorization = service.authorize(parameter(request, "form_nonce"), user, "yes".equals(approval));
                String separator = authorization.redirect.contains("?") ? "&" : "?";
                String callback = authorization.redirect + separator + (authorization.code == null
                        ? "error=access_denied" : "code=" + encode(authorization.code)) + "&state=" + encode(authorization.state);
                response.setStatus(303);
                response.setHeader("Location", callback);
                return;
            }
            if (!OboClientAuthentication.accepts(request, service)) { response.setHeader("WWW-Authenticate", "Basic realm=\"Gradial OBO\""); error(response, 401, "invalid_client"); return; }
            if (path.equals("/bin/gradial/obo/revoke")) {
                service.revoke(parameter(request, "token"));
                response.setStatus(200);
                return;
            }
            if (!path.equals("/bin/gradial/obo/token")) { response.setStatus(404); return; }
            String grantType = parameter(request, "grant_type");
            OboService.Tokens tokens;
            if ("authorization_code".equals(grantType)) {
                tokens = service.exchange(parameter(request, "code"), parameter(request, "redirect_uri"), parameter(request, "code_verifier"));
            } else if ("refresh_token".equals(grantType)) {
                tokens = service.refresh(parameter(request, "refresh_token"));
            } else { error(response, 400, "unsupported_grant_type"); return; }
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write("{\"access_token\":\"" + tokens.access + "\",\"refresh_token\":\""
                    + tokens.refresh + "\",\"token_type\":\"GradialOBO\",\"expires_in\":" + tokens.expiresIn + "}");
        } catch (OboService.InvalidDelegationException | IllegalArgumentException e) { error(response, 400, "invalid_grant"); }
        catch (RepositoryException e) { error(response, 503, "temporarily_unavailable"); }
    }

    private static String browserUser(SlingHttpServletRequest request) throws RepositoryException {
        String user = request.getResourceResolver().getUserID();
        if (user == null || "anonymous".equals(user) || OboService.SCHEME.equals(request.getAuthType())) throw OboService.invalid();
        return user;
    }

    private static String parameter(SlingHttpServletRequest request, String name) {
        String[] values = request.getParameterValues(name);
        if (values == null || values.length != 1 || values[0].length() > 2048) throw new IllegalArgumentException("Invalid parameter");
        return values[0];
    }
    private static String encode(String value) { return URLEncoder.encode(value, StandardCharsets.UTF_8); }
    private static String html(String value) {
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;");
    }
    private static void headers(SlingHttpServletResponse response) {
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Pragma", "no-cache");
        response.setHeader("Referrer-Policy", "no-referrer");
        response.setHeader("X-Content-Type-Options", "nosniff");
    }
    private static void error(SlingHttpServletResponse response, int status, String error) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write("{\"error\":\"" + error + "\"}");
    }
}
