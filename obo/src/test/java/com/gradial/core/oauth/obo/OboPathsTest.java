package com.gradial.core.oauth.obo;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class OboPathsTest {
    @Test
    void normalizationMatchesWhatTheContainerServes() {
        assertEquals("/crx/packmgr", OboPaths.normalize("/crx/%70ackmgr"));
        assertEquals("/crx/packmgr", OboPaths.normalize("//crx///packmgr/"));
        assertEquals("/crx/packmgr", OboPaths.normalize("/content/./../crx/packmgr?x=1"));
        assertEquals("/etc/packages/a.zip", OboPaths.normalize("/etc/packages;jsessionid=1/a.zip"));
        assertNull(OboPaths.normalize("/../crx"));
        assertNull(OboPaths.normalize("/crx%2"));
        assertNull(OboPaths.normalize("/crx\\packmgr"));
        assertNull(OboPaths.normalize("relative"));
        assertEquals("/", OboPaths.normalize("/"));
    }

    @Test
    void theBaselineCannotBeConfiguredAway() {
        OboPaths paths = OboPaths.of(new String[] {"/only-this"});
        assertTrue(paths.refuses("POST", "/bin/gradial/obo/token"));
        assertTrue(paths.refuses("POST", "/oauth/token"));
        assertTrue(paths.refuses("GET", "/libs/granite/oauth/content/clients.html"));
        assertTrue(paths.refuses("GET", "/only-this.json"));
        assertFalse(paths.refuses("GET", "/crx/packmgr"), "a customer may opt out of the defaults");
    }

    @Test
    void prefixesCoverDescendantsSelectorsAndExtensionsButNotSiblings() {
        OboPaths paths = OboPaths.of(null);
        assertTrue(paths.refuses("GET", "/crx"));
        assertTrue(paths.refuses("GET", "/crx.html"));
        assertTrue(paths.refuses("GET", "/crx/de"));
        assertFalse(paths.refuses("GET", "/crxfoo"));
        assertFalse(paths.refuses("GET", "/content/crx"));
    }

    @Test
    void writeEntriesRefuseOnlyMutationsAndIdentityReadsStayAvailable() {
        OboPaths paths = OboPaths.of(null);
        assertFalse(paths.refuses("GET", "/home/users/a/author.json"));
        assertTrue(paths.refuses("POST", "/home/users/a/author"));
        assertTrue(paths.refuses("DELETE", "/etc/replication/agents.author/publish"));
        assertFalse(paths.refuses("GET", "/libs/granite/security/currentuser.json"));
        assertTrue(paths.refuses("POST", "/libs/granite/security/currentuser.json"));
        assertTrue(paths.refuses("GET", "/libs/granite/security/search/authorizables.json"));
        for (String content : new String[] {"/content/site", "/content/dam/a.jpg", "/api/assets/x.json", "/bin/querybuilder.json",
                "/bin/replicate.json", "/bin/wcmcommand", "/libs/granite/csrf/token.json", "/conf/site/settings/wcm/templates"}) {
            assertFalse(paths.refuses("POST", content), content);
        }
    }
}
