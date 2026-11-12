package com.gradial.core.oauth.obo;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.apache.felix.framework.Felix;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.osgi.framework.Bundle;
import org.osgi.framework.Constants;
import org.osgi.framework.wiring.BundleWire;
import org.osgi.framework.wiring.BundleWiring;
import org.osgi.framework.wiring.FrameworkWiring;

/**
 * gradial.obo must resolve on both supported AEM lines. Its Oak imports are checked against the
 * {@code Export-Package} headers of the real Oak bundles each line runs (AEM 6.5 SP25: Oak 1.22.24,
 * AEM 6.5 LTS: Oak 1.88.0), copied into target/platforms by maven-dependency-plugin; nothing stubs an
 * Oak package. Other imports are exported by a stub at the lowest version they accept.
 *
 * <p>Round-three review: a build against the 6.5.8 uber-jar imported
 * {@code org.apache.jackrabbit.oak.spi.security.principal;version="[1.8,2)"}, which Oak 1.88.0 exports
 * at 2.1.1. That package is no longer imported; the control below shows the old import fails on LTS.
 */
class ImportPackageResolutionTest {
    private static final Path CLASSES = Paths.get("target/classes");
    private static final Path PLATFORMS = Paths.get("target/platforms");
    private static final String PRINCIPAL = "org.apache.jackrabbit.oak.spi.security.principal";

    @TempDir
    Path temp;

    @Test
    void theOakPrincipalSpiIsNotImported() throws Exception {
        assertFalse(imports(manifest()).containsKey(PRINCIPAL));
    }

    @Test
    void gradialOboResolvesAgainstTheOakBundlesOfAem65Sp25AndAem65Lts() throws Exception {
        Manifest manifest = manifest();
        File obo = jarOf(manifest, "gradial-obo.jar");
        for (String platform : new String[] {"aem65-sp25", "aem65-lts"}) {
            Map<String, String> oak = oakExports(platform);
            Result result = resolve(obo, oak, manifest, platform);
            assertEquals(Bundle.RESOLVED, result.state, "gradial.obo resolves on " + platform);
            for (String pkg : imports(manifest).keySet()) {
                if (pkg.startsWith("org.apache.jackrabbit.oak.")) {
                    assertEquals("zz.platform.oak", result.wiredTo.get(pkg), pkg + " is wired to the real " + platform + " export");
                }
            }
            System.out.println(platform + " Oak exports used: " + result.oakVersions);
        }
    }

    @Test
    void controlTheOldPrincipalImportDoesNotResolveOnLts() throws Exception {
        Manifest manifest = manifest();
        String header = manifest.getMainAttributes().getValue(Constants.IMPORT_PACKAGE);
        manifest.getMainAttributes().putValue(Constants.IMPORT_PACKAGE, header + "," + PRINCIPAL + ";version=\"[1.8,2)\"");
        File old = jarOf(manifest, "gradial-obo-old-import.jar");
        assertEquals(Bundle.INSTALLED, resolve(old, oakExports("aem65-lts"), manifest, "lts-control").state);
        assertEquals(Bundle.RESOLVED, resolve(old, oakExports("aem65-sp25"), manifest, "sp25-control").state);
    }

    // --- helpers ---

    private static Manifest manifest() throws IOException {
        try (InputStream in = new FileInputStream(CLASSES.resolve("META-INF/MANIFEST.MF").toFile())) {
            return new Manifest(in);
        }
    }

    /** Splits an OSGi header into clauses at commas outside quotes. */
    static List<String> clauses(String header) {
        List<String> out = new ArrayList<>();
        if (header == null) return out;
        StringBuilder current = new StringBuilder();
        boolean quoted = false;
        for (char c : header.toCharArray()) {
            if (c == '"') quoted = !quoted;
            if (c == ',' && !quoted) {
                out.add(current.toString().trim());
                current.setLength(0);
            } else {
                current.append(c);
            }
        }
        if (current.length() > 0) out.add(current.toString().trim());
        return out;
    }

    private static Map<String, String> imports(Manifest manifest) {
        Map<String, String> imports = new LinkedHashMap<>();
        for (String clause : clauses(manifest.getMainAttributes().getValue(Constants.IMPORT_PACKAGE))) {
            imports.put(clause.split(";", 2)[0], clause);
        }
        return imports;
    }

    /** Every Export-Package clause of the platform's real Oak bundles, by package. */
    private static Map<String, String> oakExports(String platform) throws IOException {
        Map<String, String> exports = new LinkedHashMap<>();
        try (Stream<Path> jars = Files.list(PLATFORMS.resolve(platform))) {
            for (Path jar : (Iterable<Path>) jars.filter(p -> p.toString().endsWith(".jar"))::iterator) {
                try (JarFile file = new JarFile(jar.toFile())) {
                    for (String clause : clauses(file.getManifest().getMainAttributes().getValue(Constants.EXPORT_PACKAGE))) {
                        // Keep package and version only: the resolver needs no uses: constraints on a manifest-only stub.
                        String pkg = clause.split(";", 2)[0];
                        Matcher v = Pattern.compile("version=\"?([0-9][0-9.]*)").matcher(clause);
                        exports.put(pkg, pkg + ";version=\"" + (v.find() ? v.group(1) : "0.0.0") + "\"");
                    }
                }
            }
        }
        assertFalse(exports.isEmpty(), "Oak bundles for " + platform + " were copied into " + PLATFORMS);
        return exports;
    }

    private static final class Result {
        final int state;
        final Map<String, String> wiredTo = new HashMap<>();
        final Map<String, Object> oakVersions = new java.util.TreeMap<>();
        Result(int state) { this.state = state; }
    }

    private Result resolve(File bundleJar, Map<String, String> oak, Manifest manifest, String name) throws Exception {
        Map<String, Object> config = new HashMap<>();
        config.put(Constants.FRAMEWORK_STORAGE, temp.resolve("fw-" + name).toString());
        config.put(Constants.FRAMEWORK_STORAGE_CLEAN, Constants.FRAMEWORK_STORAGE_CLEAN_ONFIRSTINIT);
        Felix felix = new Felix(config);
        felix.init();
        felix.start();
        try {
            felix.getBundleContext().installBundle(stub("zz.platform.oak", new ArrayList<>(oak.values()), Collections.emptyList(),
                    name + "-oak.jar").toURI().toString());
            felix.getBundleContext().installBundle(otherImportsStub(manifest, oak.keySet(), name).toURI().toString());
            Bundle bundle = felix.getBundleContext().installBundle(bundleJar.toURI().toString());
            felix.adapt(FrameworkWiring.class).resolveBundles(Collections.singleton(bundle));
            Result result = new Result(bundle.getState());
            BundleWiring wiring = bundle.adapt(BundleWiring.class);
            if (wiring != null) {
                for (BundleWire wire : wiring.getRequiredWires("osgi.wiring.package")) {
                    String pkg = (String) wire.getCapability().getAttributes().get("osgi.wiring.package");
                    result.wiredTo.put(pkg, wire.getProvider().getBundle().getSymbolicName());
                    if (pkg.startsWith("org.apache.jackrabbit.oak.")) {
                        result.oakVersions.put(pkg, wire.getCapability().getAttributes().get("version"));
                    }
                }
            }
            return result;
        } finally {
            felix.stop();
            felix.waitForStop(10000);
        }
    }

    /** Exports every non-Oak import at its lowest accepted version, and the extenders the manifest requires. */
    private File otherImportsStub(Manifest manifest, Set<String> oakPackages, String name) throws IOException {
        List<String> exports = new ArrayList<>();
        for (Map.Entry<String, String> entry : imports(manifest).entrySet()) {
            String pkg = entry.getKey();
            if (pkg.startsWith("java.") || pkg.startsWith("org.apache.jackrabbit.oak.") || oakPackages.contains(pkg)) continue;
            exports.add(pkg + ";version=\"" + floor(entry.getValue()) + "\"");
        }
        List<String> provides = new ArrayList<>();
        Pattern extender = Pattern.compile("osgi\\.extender=([^)]+)\\)\\(version>=([0-9.]+)");
        for (String requirement : clauses(manifest.getMainAttributes().getValue(Constants.REQUIRE_CAPABILITY))) {
            String namespace = requirement.split(";", 2)[0];
            if (namespace.equals("osgi.ee") || requirement.contains("effective:=active")) continue;
            Matcher m = extender.matcher(requirement);
            assertTrue(namespace.equals("osgi.extender") && m.find(), "unexpected resolve-time requirement " + requirement);
            provides.add("osgi.extender;osgi.extender=" + m.group(1) + ";version:Version=" + m.group(2));
        }
        return stub("zz.platform.other", exports, provides, name + "-other.jar");
    }

    private File stub(String symbolicName, List<String> exports, List<String> provides, String file) throws IOException {
        Manifest manifest = new Manifest();
        Attributes main = manifest.getMainAttributes();
        main.put(Attributes.Name.MANIFEST_VERSION, "1.0");
        main.putValue(Constants.BUNDLE_MANIFESTVERSION, "2");
        main.putValue(Constants.BUNDLE_SYMBOLICNAME, symbolicName);
        main.putValue(Constants.BUNDLE_VERSION, "1.0.0");
        if (!exports.isEmpty()) main.putValue(Constants.EXPORT_PACKAGE, String.join(",", exports));
        if (!provides.isEmpty()) main.putValue(Constants.PROVIDE_CAPABILITY, String.join(",", provides));
        File jar = temp.resolve(file).toFile();
        try (JarOutputStream out = new JarOutputStream(new FileOutputStream(jar), manifest)) {
            // Manifest only.
        }
        return jar;
    }

    private File jarOf(Manifest manifest, String name) throws IOException {
        File jar = temp.resolve(name).toFile();
        try (JarOutputStream out = new JarOutputStream(new FileOutputStream(jar), manifest);
             Stream<Path> files = Files.walk(CLASSES)) {
            for (Path f : (Iterable<Path>) files.filter(Files::isRegularFile)::iterator) {
                String entry = CLASSES.relativize(f).toString().replace(File.separatorChar, '/');
                if ("META-INF/MANIFEST.MF".equals(entry)) continue;
                out.putNextEntry(new JarEntry(entry));
                Files.copy(f, out);
                out.closeEntry();
            }
        }
        return jar;
    }

    /** The lowest version an import clause accepts. */
    static String floor(String clause) {
        Matcher m = Pattern.compile("version=\"?[\\[(]?([0-9][0-9.]*)").matcher(clause);
        return m.find() ? m.group(1) : "0.0.0";
    }
}
