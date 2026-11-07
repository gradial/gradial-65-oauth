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
    @Reference
    private OboImpersonationGuard guard;

    @Override
    protected void doGet(SlingHttpServletRequest request, SlingHttpServletResponse response) throws IOException {
        headers(response);
        if (!request.getRequestURI().equals("/bin/gradial/obo/authorize")) { response.setStatus(405); return; }
        try {
            String user = browserUser(request);
            if (!"code".equals(parameter(request, "response_type"))
                    || !"S256".equals(parameter(request, "code_challenge_method"))) throw OboService.invalid();
            String redirect = parameter(request, "redirect_uri");
            String nonce = service.consent(user, parameter(request, "client_id"), redirect,
                    parameter(request, "code_challenge"), parameter(request, "state"));
            String callbackOrigin = OboService.checkedUri(redirect).resolve("/").toASCIIString();
            String scriptNonce = OboService.random();
            // AEM's referrer filter must recognize the consent POST; callbacks remain cross-origin private.
            response.setHeader("Referrer-Policy", "same-origin");
            String styleNonce = OboService.random();
            response.setHeader("Content-Security-Policy", "default-src 'none'; script-src 'nonce-" + scriptNonce
                    + "'; style-src 'nonce-" + styleNonce + "'; connect-src 'self'; form-action 'self' " + callbackOrigin
                    + "; frame-ancestors 'none'; base-uri 'none'");
            response.setContentType("text/html;charset=UTF-8");
            response.getWriter().write(consentPage(user, nonce, scriptNonce, styleNonce));
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

    /**
     * The person consenting must be the person who signed in. A delegated credential or an AEM
     * "Impersonate as" session would let someone approve a grant the named user never saw.
     */
    private String browserUser(SlingHttpServletRequest request) throws RepositoryException {
        String user = request.getResourceResolver().getUserID();
        if (user == null || "anonymous".equals(user) || OboService.SCHEME.equals(request.getAuthType())
                || guard.impersonated(request)) throw OboService.invalid();
        return user;
    }

    private static String parameter(SlingHttpServletRequest request, String name) {
        String[] values = request.getParameterValues(name);
        if (values == null || values.length != 1 || values[0].length() > 2048) throw new IllegalArgumentException("Invalid parameter");
        return values[0];
    }
    private static String encode(String value) { return URLEncoder.encode(value, StandardCharsets.UTF_8); }
    // Colors mirror the Gradial web app theme tokens (light and dark) so this AEM-hosted page matches the app.
    private static final String CONSENT_STYLE = ":root{color-scheme:light dark;--bg:#fff;--fg:#0a0a0a;--muted:#737373;--card:#fff;"
            + "--border:#e5e5e5;--input:#e5e5e5;--primary:#2b7fff;--primary-fg:#fafafa;--secondary:#f5f5f5;--secondary-fg:#171717;"
            + "--destructive:#e7000b;--tile:#0a0a0a;--tile-fg:#fafafa;--ring:#a1a1a1}"
            + "@media(prefers-color-scheme:dark){:root{--bg:#0a0a0a;--fg:#fafafa;--muted:#a1a1a1;--card:#171717;--border:#ffffff1a;"
            + "--input:#ffffff26;--secondary:#262626;--secondary-fg:#fafafa;--destructive:#ff6467;--tile:#262626;--ring:#737373}}"
            + "*{box-sizing:border-box}"
            + "body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:1.5rem;background:var(--bg);"
            + "color:var(--fg);font:14px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif}"
            + "main{width:100%;max-width:26rem;background:var(--card);border:1px solid var(--border);border-radius:.75rem;padding:1.5rem}"
            + ".logo{display:flex;align-items:center;justify-content:center;width:2.5rem;height:2.5rem;border-radius:.5rem;"
            + "background:var(--tile);color:var(--tile-fg)}"
            + ".logo svg{width:1.5rem;height:1.5rem}"
            + "h1{margin:1.5rem 0 0;font-size:1.25rem;line-height:1.75rem;font-weight:500;text-wrap:balance}"
            + "p{margin:.5rem 0 0;color:var(--muted)}"
            + "form{margin:0}.actions{display:flex;flex-direction:row-reverse;gap:.75rem;margin-top:1.5rem}"
            + "button{flex:1;height:2.25rem;border-radius:9999px;border:1px solid var(--input);padding:0 1rem;font:inherit;"
            + "font-weight:500;cursor:pointer;background:var(--secondary);color:var(--secondary-fg)}"
            + "button[value=yes]{background:var(--primary);border-color:var(--primary);color:var(--primary-fg)}"
            + "button:focus-visible{outline:2px solid var(--ring);outline-offset:2px}"
            + "button:disabled{opacity:.5;cursor:not-allowed}"
            + "#error{margin-top:1rem;padding:.625rem .75rem;border:1px solid var(--destructive);border-radius:.5rem;"
            + "color:var(--destructive)}#error:empty{display:none}";

    private static final String LOGO = "<svg xmlns='http://www.w3.org/2000/svg' viewBox='-5 -5 220 290' fill='currentColor' aria-hidden='true'>"
            + "<path d='M98.38,58.26h50.61C181.17,58.26,207.25,32.18,207.25,0h0s-105.62,0-105.62,0C40.65,0,.94,43.63.94,97.44s43.63,97.44,97.44,97.44,97.44-43.63,97.44-97.44c0-5.82-.74-11.65-2.11-17.05h-60.05c2.49,5.15,3.89,10.94,3.89,17.05,0,21.64-17.54,39.18-39.18,39.18s-39.18-17.54-39.18-39.18,17.54-39.18,39.18-39.18Z'/>"
            + "<path d='M140.15,224.63h-68.5c-10.98,0-19.88-8.9-19.88-19.88v-21.72h0c-22.98,0-41.6,18.63-41.61,41.6h0s0,0,0,0,0,0,0,0h0s0,0,0,0c0,31.4,25.46,56.86,56.87,56.86h129.99c0-31.41-25.46-56.87-56.87-56.87Z'/></svg>";

    static String consentPage(String user, String formNonce, String scriptNonce, String styleNonce) {
        return "<!doctype html><html lang=en><head><meta charset=utf-8>"
                + "<meta name=viewport content='width=device-width,initial-scale=1'><title>Connect Gradial</title>"
                + "<style nonce='" + styleNonce + "'>" + CONSENT_STYLE + "</style></head><body><main>"
                + "<div class=logo>" + LOGO + "</div>"
                + "<h1>Connect Gradial as " + html(user) + "</h1>"
                + "<p>Gradial will use your current AEM permissions. You can revoke this connection from Gradial.</p>"
                + "<form method=post action='/bin/gradial/obo/authorize'><input type=hidden name=form_nonce value='"
                + formNonce + "'><input id=csrf type=hidden name=':cq_csrf_token'>"
                + "<div class=actions><button name=approve value=yes disabled>Connect</button>"
                + "<button name=approve value=no disabled>Cancel</button></div>"
                + "</form><p id=error role=alert></p><script nonce='" + scriptNonce + "'>"
                + "fetch('/libs/granite/csrf/token.json',{credentials:'same-origin'}).then(r=>{if(!r.ok)throw Error();return r.json()})"
                + ".then(t=>{if(!t.token)throw Error();document.getElementById('csrf').value=t.token;"
                + "document.querySelectorAll('button').forEach(b=>b.disabled=false)})"
                + ".catch(()=>document.getElementById('error').textContent='Sign into AEM and try again.');</script></main></body></html>";
    }

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
