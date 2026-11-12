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
    void exactlyTheFixedEndpointsAreRefused() {
        assertEquals(java.util.Arrays.asList("/bin/gradial/obo", "/oauth", "/libs/granite/oauth", "/crx/packmgr", "/crx/de",
                "/crx/server", "/libs/granite/security", "/system/console"), OboPaths.REFUSED);
        for (String uri : new String[] {"/bin/gradial/obo/token", "/oauth/token", "/libs/granite/oauth/content/clients.html",
                "/crx/packmgr/service.jsp", "/crx/de/index.jsp", "/crx/server/crx.default/jcr:root", "/libs/granite/security/post/authorizables",
                "/system/console/configMgr", "/system/console.json", "/OAUTH/token"}) {
            assertTrue(OboPaths.refuses("POST", uri), uri);
            assertTrue(OboPaths.refuses("GET", uri), uri);
        }
    }

    @Test
    void prefixesCoverDescendantsSelectorsAndExtensionsButNotSiblings() {
        assertTrue(OboPaths.refuses("GET", "/crx/de"));
        assertTrue(OboPaths.refuses("GET", "/crx/de.html"));
        assertFalse(OboPaths.refuses("GET", "/crx/defaults"));
        assertFalse(OboPaths.refuses("GET", "/content/crx/de"));
        assertFalse(OboPaths.refuses("GET", "/oauthx"));
    }

    @Test
    void identityReadsStayAvailableAndEverythingElseIsLeftToAcls() {
        for (String identity : new String[] {"/libs/granite/security/currentuser.json", "/libs/granite/security/whoami.json",
                "/libs/granite/security/userinfo.json", "/libs/granite/security/currentuser.json?props=memberOf"}) {
            assertFalse(OboPaths.refuses("GET", identity), identity);
            assertFalse(OboPaths.refuses("HEAD", identity), identity);
            assertTrue(OboPaths.refuses("POST", identity), identity);
        }
        assertTrue(OboPaths.refuses("GET", "/libs/granite/security/search/authorizables.json"));
        for (String content : new String[] {"/content/site", "/content/dam/a.jpg", "/api/assets/x.json", "/bin/querybuilder.json",
                "/bin/replicate.json", "/bin/wcmcommand", "/libs/granite/csrf/token.json", "/conf/site/settings/wcm/templates",
                "/etc/packages/x.zip", "/home/users/a/author", "/etc/cloudservices/x", "/crx"}) {
            assertFalse(OboPaths.refuses("POST", content), content);
        }
    }
}
