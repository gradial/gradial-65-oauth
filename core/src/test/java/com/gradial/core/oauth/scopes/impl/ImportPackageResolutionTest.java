package com.gradial.core.oauth.scopes.impl;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
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
 * gradial.core must resolve, and its scope registrars must load, on an AEM where Sling repoinit
 * ({@code org.apache.sling.repoinit.parser}, {@code org.apache.sling.jcr.repoinit}) is not available.
 * A mandatory import of either would leave the bundle INSTALLED, and every OAuth scope it registers
 * would disappear.
 *
 * <p>The resolver check runs the real Apache Felix framework on the manifest bnd generated into
 * target/classes, against a generated bundle that exports every other package and capability that
 * manifest requires.
 */
class ImportPackageResolutionTest {
    private static final Set<String> REPOINIT = new HashSet<>(Arrays.asList(
            "org.apache.sling.repoinit.parser", "org.apache.sling.jcr.repoinit"));
    private static final Path CLASSES = Paths.get("target/classes");

    @TempDir
    Path temp;

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

    @Test
    void bothRepoinitPackagesAreOptionalImports() throws Exception {
        Map<String, String> imports = imports(manifest());
        for (String pkg : REPOINIT) {
            String clause = imports.get(pkg);
            assertNotNull(clause, pkg + " is imported");
            assertTrue(clause.contains("resolution:=optional"), clause);
            System.out.println("Import-Package clause: " + clause);
        }
    }

    @Test
    void theBundleResolvesWithoutRepoinitAndDoesNotWithoutAMandatoryPackage() throws Exception {
        Manifest manifest = manifest();
        File core = jarOf(manifest, "gradial-core.jar");

        Result resolved = resolve(core, stub(manifest, REPOINIT, "stub-without-repoinit.jar"), "without-repoinit");
        assertEquals(Bundle.RESOLVED, resolved.state, "gradial.core resolves with repoinit absent");
        assertTrue(resolved.wiredPackages.contains("com.adobe.granite.oauth.server"));
        for (String pkg : REPOINIT) assertFalse(resolved.wiredPackages.contains(pkg));

        // Control: the same check fails when a mandatory import is missing, so it can detect the regression.
        Set<String> withoutGranite = new HashSet<>(REPOINIT);
        withoutGranite.add("com.adobe.granite.oauth.server");
        Result unresolved = resolve(core, stub(manifest, withoutGranite, "stub-without-granite.jar"), "without-granite");
        assertEquals(Bundle.INSTALLED, unresolved.state);
    }

    @Test
    void scopeRegistrarsLoadWithoutRepoinitClasses() throws Exception {
        try (HidingLoader loader = new HidingLoader(REPOINIT)) {
            for (String name : new String[] {DynamicScopeRegistrar.class.getName(),
                    DynamicScopeRegistrar.class.getName() + "$ConfiguredScope", ScopeReaderReady.class.getName()}) {
                Class<?> type = Class.forName(name, true, loader);
                assertSame(loader, type.getClassLoader());
                type.getDeclaredMethods();
                type.getDeclaredFields();
            }
            // Control: the initializer, the only user of repoinit types, cannot link there.
            Class<?> initializer = Class.forName(ScopeReaderRepositoryInitializer.class.getName(), false, loader);
            assertThrows(NoClassDefFoundError.class, initializer::getDeclaredFields);
        }
    }

    /** Loads com.gradial classes from target/classes itself and hides the given packages. */
    private static final class HidingLoader extends URLClassLoader {
        private final Set<String> hidden;

        HidingLoader(Set<String> hidden) throws IOException {
            super(new URL[] {CLASSES.toUri().toURL()}, ImportPackageResolutionTest.class.getClassLoader());
            this.hidden = hidden;
        }

        @Override
        protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
            int dot = name.lastIndexOf('.');
            if (dot > 0 && hidden.contains(name.substring(0, dot))) throw new ClassNotFoundException(name);
            if (name.startsWith("com.gradial.")) {
                synchronized (getClassLoadingLock(name)) {
                    Class<?> loaded = findLoadedClass(name);
                    if (loaded == null) loaded = findClass(name);
                    if (resolve) resolveClass(loaded);
                    return loaded;
                }
            }
            return super.loadClass(name, resolve);
        }
    }

    /** gradial.core's state after resolution, and the packages it is wired to, captured before the framework stops. */
    private static final class Result {
        final int state;
        final Set<Object> wiredPackages = new HashSet<>();
        Result(int state) { this.state = state; }
    }

    private Result resolve(File core, File stub, String name) throws Exception {
        Map<String, Object> config = new HashMap<>();
        config.put(Constants.FRAMEWORK_STORAGE, temp.resolve(name).toString());
        config.put(Constants.FRAMEWORK_STORAGE_CLEAN, Constants.FRAMEWORK_STORAGE_CLEAN_ONFIRSTINIT);
        Felix felix = new Felix(config);
        felix.init();
        felix.start();
        try {
            felix.getBundleContext().installBundle(stub.toURI().toString());
            Bundle bundle = felix.getBundleContext().installBundle(core.toURI().toString());
            felix.adapt(FrameworkWiring.class).resolveBundles(Collections.singleton(bundle));
            Result result = new Result(bundle.getState());
            BundleWiring wiring = bundle.adapt(BundleWiring.class);
            if (wiring != null) {
                for (BundleWire wire : wiring.getRequiredWires("osgi.wiring.package")) {
                    result.wiredPackages.add(wire.getCapability().getAttributes().get("osgi.wiring.package"));
                }
            }
            return result;
        } finally {
            felix.stop();
            felix.waitForStop(10000);
        }
    }

    private File jarOf(Manifest manifest, String name) throws IOException {
        File jar = temp.resolve(name).toFile();
        try (JarOutputStream out = new JarOutputStream(new FileOutputStream(jar), manifest);
             Stream<Path> files = Files.walk(CLASSES)) {
            for (Path file : (Iterable<Path>) files.filter(Files::isRegularFile)::iterator) {
                String entry = CLASSES.relativize(file).toString().replace(File.separatorChar, '/');
                if ("META-INF/MANIFEST.MF".equals(entry)) continue;
                out.putNextEntry(new JarEntry(entry));
                Files.copy(file, out);
                out.closeEntry();
            }
        }
        return jar;
    }

    /** A bundle exporting every package gradial.core imports except {@code omit}, at its lowest version. */
    private File stub(Manifest core, Set<String> omit, String name) throws IOException {
        List<String> exports = new ArrayList<>();
        for (Map.Entry<String, String> entry : imports(core).entrySet()) {
            if (omit.contains(entry.getKey()) || entry.getKey().startsWith("java.")) continue;
            exports.add(entry.getKey() + ";version=\"" + floor(entry.getValue()) + "\"");
        }
        List<String> provides = new ArrayList<>();
        Pattern extender = Pattern.compile("osgi\\.extender=([^)]+)\\)\\(version>=([0-9.]+)");
        for (String requirement : clauses(core.getMainAttributes().getValue(Constants.REQUIRE_CAPABILITY))) {
            String namespace = requirement.split(";", 2)[0];
            if (namespace.equals("osgi.ee") || requirement.contains("effective:=active")) continue;
            Matcher m = extender.matcher(requirement);
            assertTrue(namespace.equals("osgi.extender") && m.find(), "unexpected resolve-time requirement " + requirement);
            provides.add("osgi.extender;osgi.extender=" + m.group(1) + ";version:Version=" + m.group(2));
        }
        Manifest manifest = new Manifest();
        Attributes main = manifest.getMainAttributes();
        main.put(Attributes.Name.MANIFEST_VERSION, "1.0");
        main.putValue(Constants.BUNDLE_MANIFESTVERSION, "2");
        main.putValue(Constants.BUNDLE_SYMBOLICNAME, "zz.stub.provider");
        main.putValue(Constants.BUNDLE_VERSION, "1.0.0");
        main.putValue(Constants.EXPORT_PACKAGE, String.join(",", exports));
        if (!provides.isEmpty()) main.putValue(Constants.PROVIDE_CAPABILITY, String.join(",", provides));
        File jar = temp.resolve(name).toFile();
        try (JarOutputStream out = new JarOutputStream(new FileOutputStream(jar), manifest)) {
            // Manifest only.
        }
        return jar;
    }

    /** The lowest version an import clause accepts. */
    static String floor(String clause) {
        Matcher m = Pattern.compile("version=\"?[\\[(]?([0-9][0-9.]*)").matcher(clause);
        return m.find() ? m.group(1) : "0.0.0";
    }
}
