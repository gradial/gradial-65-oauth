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
        return RepositoryInitScriptTest.shippedScript();
    }

    @Test
    void storeParentsAreNonOrderableAndEveryoneCanNeitherReadNorWriteThem() throws Exception {
        String script = script();
        // sling:Folder is a valid child of nt:folder, sling:(Ordered)Folder and unstructured parents, and is not orderable.
        assertTrue(script.contains("create path (sling:Folder) /var/gradial/obo/grants"));
        assertTrue(script.contains("create path (sling:Folder) /var/gradial/obo/consents"));
        assertFalse(script.contains("nt:unstructured"));
        assertFalse(script.contains("(oak:Unstructured)"), "oak:Unstructured cannot be created under an existing nt:folder");
        String everyone = script.substring(script.indexOf("set ACL for everyone"), script.indexOf("set ACL for administrators"));
        assertTrue(everyone.contains("deny jcr:read,rep:write on /var/gradial/obo"));
        assertFalse(script.contains("jcr:write,rep:write"), "rep:write already contains jcr:write");
        assertTrue(script.indexOf("set ACL for administrators") > script.indexOf("set ACL for everyone"),
                "the administrators allow follows the everyone deny so it wins");
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
