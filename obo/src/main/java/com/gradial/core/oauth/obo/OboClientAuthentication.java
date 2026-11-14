package com.gradial.core.oauth.obo;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.servlet.http.HttpServletRequest;

/** RFC 6749 2.3.1 confidential-client authentication: HTTP Basic or body parameters, never both. */
final class OboClientAuthentication {
    private OboClientAuthentication() { }

    static boolean accepts(HttpServletRequest request, OboService service) {
        try {
            String authorization = request.getHeader("Authorization");
            if (authorization != null) {
                if (!OboAuthenticationHandler.isBasic(authorization) || authorization.length() > 2048
                        || request.getParameter("client_secret") != null || request.getParameter("client_id") != null) return false;
                String decoded = new String(Base64.getDecoder().decode(authorization.substring(6).trim()), StandardCharsets.UTF_8);
                int separator = decoded.indexOf(':');
                return separator > 0 && service.clientMatches(decode(decoded.substring(0, separator)), decode(decoded.substring(separator + 1)));
            }
            String[] client = request.getParameterValues("client_id");
            String[] secret = request.getParameterValues("client_secret");
            return client != null && client.length == 1 && secret != null && secret.length == 1
                    && service.clientMatches(client[0], secret[0]);
        } catch (IllegalArgumentException e) { return false; }
    }

    /** RFC 6749 2.3.1: the client ID and secret are form-urlencoded before Basic encoding. */
    static String decode(String value) {
        try { return URLDecoder.decode(value, "UTF-8"); }
        catch (UnsupportedEncodingException e) { throw new IllegalStateException(e); }
    }
}
