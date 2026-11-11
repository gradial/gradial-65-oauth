package com.gradial.core.oauth.obo;

import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.request.RequestParameter;
import org.apache.sling.api.resource.Resource;

/**
 * Every repository path a Sling POST request can act on, not only the resource it is addressed to: the
 * {@code :applyTo} items, a {@code :dest}, absolute or relative property paths, and {@code @MoveFrom} /
 * {@code @CopyFrom} sources. A denied path anywhere among them refuses the request.
 *
 * <p>Ordinary property values are never treated as targets: a page may legitimately store a path such as
 * {@code cq:cloudserviceconfigs=/etc/cloudservices/...}. Other POST servlets that take a target path in a
 * value (WCM commands, replication) are bounded by the user's own ACLs, as in AEM itself.
 */
final class OboRequestTargets {
    private OboRequestTargets() { }

    static Set<String> of(SlingHttpServletRequest request) {
        Set<String> targets = new LinkedHashSet<>();
        Resource resource = request.getResource();
        String base = resource != null && resource.getPath() != null ? resource.getPath()
                : request.getRequestPathInfo().getResourcePath();
        if (base == null) base = "/";
        targets.add(base);
        Map<String, RequestParameter[]> parameters = request.getRequestParameterMap();
        if (parameters == null) return targets;
        for (Map.Entry<String, RequestParameter[]> parameter : parameters.entrySet()) {
            String name = parameter.getKey();
            if (name == null) continue;
            if (":applyTo".equals(name) || ":dest".equals(name)) {
                for (String value : values(parameter.getValue())) {
                    targets.add(resolve(base, stripChildrenWildcard(value)));
                    // A relative :dest of a move or copy is resolved against the resource's parent.
                    if (":dest".equals(name)) targets.add(resolve(parent(base), value));
                }
                continue;
            }
            if (name.startsWith(":")) continue;
            String path = name.contains("@") ? name.substring(0, name.indexOf('@')) : name;
            if (path.startsWith("/") || path.contains("/") || path.startsWith(".")) targets.add(resolve(base, path));
            boolean source = name.endsWith("@MoveFrom") || name.endsWith("@CopyFrom");
            if (source) {
                for (String value : values(parameter.getValue())) targets.add(resolve(base, value));
            }
        }
        return targets;
    }

    /** Form-field values only: an uploaded file is never read as text. */
    private static Iterable<String> values(RequestParameter[] parameters) {
        Set<String> values = new LinkedHashSet<>();
        if (parameters == null) return values;
        for (RequestParameter parameter : parameters) {
            if (parameter != null && parameter.isFormField()) {
                String value = parameter.getString();
                if (value != null && !value.isEmpty()) values.add(value.trim());
            }
        }
        return values;
    }

    private static String stripChildrenWildcard(String value) {
        return value.endsWith("/*") ? value.substring(0, value.length() - 2) : value;
    }

    private static String parent(String path) {
        int slash = path.lastIndexOf('/');
        return slash <= 0 ? "/" : path.substring(0, slash);
    }

    /** An absolute path as is; a relative one against the base. Normalization happens in OboPaths. */
    static String resolve(String base, String path) {
        if (path.startsWith("/")) return path;
        return ("/".equals(base) ? "" : base) + "/" + path;
    }
}
