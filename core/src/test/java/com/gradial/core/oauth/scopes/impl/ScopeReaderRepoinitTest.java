package com.gradial.core.oauth.scopes.impl;

import static org.junit.jupiter.api.Assertions.*;

import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

import javax.jcr.Node;
import javax.jcr.Repository;
import javax.jcr.Session;
import javax.jcr.SimpleCredentials;

import org.apache.jackrabbit.api.JackrabbitSession;
import org.apache.jackrabbit.oak.jcr.Jcr;
import org.apache.jackrabbit.oak.security.internal.SecurityProviderBuilder;
import org.apache.jackrabbit.oak.spi.security.ConfigurationParameters;
import org.apache.jackrabbit.oak.spi.security.user.UserConfiguration;
import org.apache.sling.jcr.repoinit.impl.JcrRepoInitOpsProcessorImpl;
import org.apache.sling.repoinit.parser.impl.RepoInitParserService;
import org.junit.jupiter.api.Test;

/**
 * Runs the shipped scope-reader repoinit script on real Oak (AEM 6.5 SP25's versions, or 6.5 LTS's on
 * JDK 14+). A failing repoinit script stops SlingRepository, so it must apply cleanly, twice.
 */
class ScopeReaderRepoinitTest {
    private static String script() throws Exception {
        String json = new String(Files.readAllBytes(Paths.get("../ui.config/src/main/content/jcr_root/apps/gradial/osgiconfig/"
                + "config.author/org.apache.sling.jcr.repoinit.RepositoryInitializer~gradial-oauth-scopes.cfg.json")), StandardCharsets.UTF_8);
        String body = json.substring(json.indexOf("[") + 1, json.lastIndexOf("]")).trim();
        return body.substring(1, body.length() - 1).replace("\\n", "\n");
    }

    @Test
    void theReaderSeesNodesButNoPropertiesAndTheScriptIsIdempotent() throws Exception {
        Map<String, Object> paths = new HashMap<>();
        paths.put("usersPath", "/home/users");
        paths.put("groupsPath", "/home/groups");
        Repository repository = new Jcr().with(SecurityProviderBuilder.newBuilder()
                .with(ConfigurationParameters.of(UserConfiguration.NAME, ConfigurationParameters.of(paths))).build())
                .createRepository();
        Session admin = repository.login(new SimpleCredentials("admin", "admin".toCharArray()));
        try {
            ((JackrabbitSession) admin).getUserManager().createUser("zz-seed", null);
            Node page = admin.getRootNode().addNode("content", "nt:unstructured").addNode("site", "nt:unstructured");
            page.setProperty("secret", "value");
            admin.save();
            for (int i = 0; i < 2; i++) {
                new JcrRepoInitOpsProcessorImpl().apply(admin, new RepoInitParserService().parse(new StringReader(script())));
                admin.save();
            }
            Session reader = admin.impersonate(new SimpleCredentials(DynamicScopeRegistrar.READER, new char[0]));
            try {
                assertTrue(reader.nodeExists("/content/site"), "the reader can test that a scope path exists");
                assertFalse(reader.nodeExists("/content/missing"));
                assertFalse(reader.propertyExists("/content/site/secret"), "the reader cannot read content");
                assertThrows(Exception.class, () -> {
                    reader.getNode("/content/site").addNode("zz");
                    reader.save();
                }, "the reader cannot write");
            } finally { reader.logout(); }
        } finally { admin.logout(); }
    }
}
