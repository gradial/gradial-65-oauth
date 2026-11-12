package com.gradial.core.oauth.obo;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.request.RequestParameter;
import org.apache.sling.api.resource.Resource;

/**
 * The repository paths a delegated Sling POST request can act on, accepted only in forms whose final
 * target is exactly known: the addressed resource, {@code :applyTo} items, a {@code :dest}, absolute
 * or relative property paths, and {@code @CopyFrom} / {@code @MoveFrom} sources.
 *
 * <p>This does not emulate Sling's own target resolution. A target value must be an absolute,
 * already-normalized path: no {@code ?}, {@code #}, {@code //}, {@code .} or {@code ..} segments, no
 * relative path, no {@code :dest} ending in {@code /} (whose final child Sling chooses) and no
 * wildcard {@code :applyTo}. A relative property name is accepted only without {@code .} or {@code ..}
 * segments, so it stays inside the addressed resource. Anything else is refused, naming the parameter.
 *
 * <p>Ordinary property values are never treated as targets: a page may legitimately store a path such
 * as {@code cq:cloudserviceconfigs=/etc/cloudservices/...}. Other POST servlets that take a target
 * path in a value (WCM commands, replication) are bounded by the user's own ACLs, as in AEM itself.
 */
final class OboRequestTargets {
    private OboRequestTargets() { }

    /** One exact repository path the request acts on, with the parameter that names it. */
    static final class Target {
        final String parameter;
        final String path;
        Target(String parameter, String path) { this.parameter = parameter; this.path = path; }
    }

    /** A target given in a form whose final repository path is not exactly known. */
    static final class UnprovableTarget extends Exception {
        private static final long serialVersionUID = 1L;
        final String parameter;
        UnprovableTarget(String parameter, String reason) {
            super(parameter + " " + reason);
            this.parameter = parameter;
        }
    }

    static List<Target> of(SlingHttpServletRequest request) throws UnprovableTarget {
        List<Target> targets = new ArrayList<>();
        Resource resource = request.getResource();
        String base = resource != null && resource.getPath() != null ? resource.getPath()
                : request.getRequestPathInfo().getResourcePath();
        if (base == null || !exactAbsolute(base)) throw new UnprovableTarget("the request path", "is not a normalized repository path");
        targets.add(new Target("the request path", base));
        // Reads change nothing, so their query parameters are not targets.
        String method = request.getMethod();
        if ("GET".equalsIgnoreCase(method) || "HEAD".equalsIgnoreCase(method)) return targets;
        Map<String, RequestParameter[]> parameters = request.getRequestParameterMap();
        if (parameters == null) return targets;
        for (Map.Entry<String, RequestParameter[]> parameter : parameters.entrySet()) {
            String name = parameter.getKey();
            if (name == null) continue;
            if (":applyTo".equals(name) || ":dest".equals(name)) {
                for (String value : values(parameter.getValue())) {
                    if (":applyTo".equals(name) && value.contains("*")) {
                        throw new UnprovableTarget(name, "must name exact paths; wildcards are not accepted for delegated sessions");
                    }
                    if (":dest".equals(name) && value.endsWith("/")) {
                        throw new UnprovableTarget(name, "must name the exact destination; a trailing / is not accepted for delegated sessions");
                    }
                    if (!exactAbsolute(value)) {
                        throw new UnprovableTarget(name, "must be an absolute, normalized repository path");
                    }
                    targets.add(new Target(name, value));
                }
                continue;
            }
            if (name.startsWith(":")) continue;
            String path = name.contains("@") ? name.substring(0, name.indexOf('@')) : name;
            targets.add(new Target(name, propertyTarget(name, path, base)));
            if (name.endsWith("@CopyFrom") || name.endsWith("@MoveFrom")) {
                for (String value : values(parameter.getValue())) {
                    if (!exactAbsolute(value)) throw new UnprovableTarget(name, "must be an absolute, normalized repository path");
                    targets.add(new Target(name, value));
                }
            }
        }
        return targets;
    }

    /** The exact repository path a property name addresses, or a refusal if it is not provable. */
    private static String propertyTarget(String name, String path, String base) throws UnprovableTarget {
        if (path.startsWith("/")) {
            if (!exactAbsolute(path)) throw new UnprovableTarget(name, "must be an absolute, normalized repository path");
            return path;
        }
        String relative = path.startsWith("./") ? path.substring(2) : ".".equals(path) ? "" : path;
        if (!relative.isEmpty() && !normalizedRelative(relative)) {
            throw new UnprovableTarget(name, "must stay inside the addressed resource (no . or .. segments)");
        }
        if (relative.isEmpty()) return base;
        return ("/".equals(base) ? "" : base) + "/" + relative;
    }

    /** Absolute and already normalized: no query, fragment, empty, . or .. segments, no trailing /. */
    static boolean exactAbsolute(String path) {
        if (path == null || !path.startsWith("/")) return false;
        if ("/".equals(path)) return true;
        return !path.endsWith("/") && normalizedRelative(path.substring(1));
    }

    private static boolean normalizedRelative(String path) {
        if (path.indexOf('?') >= 0 || path.indexOf('#') >= 0 || path.indexOf('\\') >= 0 || path.indexOf('\0') >= 0) return false;
        for (String segment : path.split("/", -1)) {
            if (segment.isEmpty() || ".".equals(segment) || "..".equals(segment)) return false;
        }
        return true;
    }

    /** Form-field values only: an uploaded file is never read as text. */
    private static List<String> values(RequestParameter[] parameters) {
        List<String> values = new ArrayList<>();
        if (parameters == null) return values;
        for (RequestParameter parameter : parameters) {
            if (parameter != null && parameter.isFormField()) {
                String value = parameter.getString();
                if (value != null) values.add(value);
            }
        }
        return values;
    }
}
