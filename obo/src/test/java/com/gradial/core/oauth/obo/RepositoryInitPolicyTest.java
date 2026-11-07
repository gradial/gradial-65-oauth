package com.gradial.core.oauth.obo;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.junit.jupiter.api.Test;

/** Guards the least-privilege shape of the service user that the Author configuration creates. */
class RepositoryInitPolicyTest {
    private static String script() throws Exception {
        Path file = Paths.get("../ui.config/src/main/content/jcr_root/apps/gradial/osgiconfig/config.author/"
                + "org.apache.sling.jcr.repoinit.RepositoryInitializer~gradial-obo.cfg.json");
        return new String(Files.readAllBytes(file), StandardCharsets.UTF_8).replace("\\n", "\n");
    }

    @Test
    void storeParentsAreNonOrderableAndEveryoneCanNeitherReadNorWriteThem() throws Exception {
        String script = script();
        assertTrue(script.contains("create path (oak:Unstructured) /var/gradial/obo/grants"));
        assertTrue(script.contains("create path (oak:Unstructured) /var/gradial/obo/consents"));
        assertFalse(script.contains("nt:unstructured"));
        String everyone = script.substring(script.indexOf("set ACL for everyone"), script.indexOf("set ACL for gradial-obo-state"));
        assertTrue(everyone.contains("deny jcr:read on /var/gradial/obo"));
        assertTrue(everyone.contains("deny jcr:write,rep:write on /var/gradial/obo"));
    }

    @Test
    void theServiceUserCannotReadPasswordsTokensOrProfilesUnderHome() throws Exception {
        String script = script();
        assertFalse(script.matches("(?s).*allow jcr:read on /home/users\\s*\\n.*"), "unrestricted read of /home/users");
        assertFalse(script.matches("(?s).*allow jcr:read on /home/groups\\s*\\n.*"), "unrestricted read of /home/groups");
        assertTrue(script.contains("allow jcr:read on /home/users restriction(rep:ntNames,rep:AuthorizableFolder,rep:User)"));
        assertTrue(script.contains("deny jcr:read on /home/users restriction(rep:itemNames,rep:password)"));
        assertTrue(script.indexOf("allow jcr:read on /home/users") < script.indexOf("deny jcr:read on /home/users"),
                "the deny must follow the allow so it wins");
    }
}
