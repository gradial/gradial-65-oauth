package com.gradial.core.oauth.obo;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.lang.reflect.Field;
import java.util.Dictionary;
import java.util.Hashtable;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.resource.ResourceResolver;
import org.junit.jupiter.api.Test;
import org.osgi.service.cm.Configuration;
import org.osgi.service.cm.ConfigurationAdmin;

class OboImpersonationGuardTest {
    private static OboImpersonationGuard guard(ConfigurationAdmin admin) throws Exception {
        OboImpersonationGuard guard = new OboImpersonationGuard();
        Field field = OboImpersonationGuard.class.getDeclaredField("configurationAdmin");
        field.setAccessible(true);
        field.set(guard, admin);
        return guard;
    }

    @Test
    void defaultNamesAreRefusedWithoutAnyConfiguration() throws Exception {
        OboImpersonationGuard guard = guard(null);
        assertFalse(guard.impersonationRequested(mock(HttpServletRequest.class)));
        HttpServletRequest cookie = mock(HttpServletRequest.class);
        when(cookie.getCookies()).thenReturn(new Cookie[] {new Cookie("sling.sudo", "Ym9i")});
        assertTrue(guard.impersonationRequested(cookie));
        HttpServletRequest empty = mock(HttpServletRequest.class);
        when(empty.getCookies()).thenReturn(new Cookie[] {new Cookie("sling.sudo", "")});
        assertFalse(guard.impersonationRequested(empty));
        for (String name : new String[] {"sudo", "sling.sudo"}) {
            HttpServletRequest parameter = mock(HttpServletRequest.class);
            when(parameter.getParameter(name)).thenReturn("");
            assertTrue(guard.impersonationRequested(parameter));
        }
    }

    @Test
    void namesConfiguredInSlingAuthenticatorAreHonoredToo() throws Exception {
        Dictionary<String, Object> properties = new Hashtable<>();
        properties.put("auth.sudo.cookie", "my.sudo");
        properties.put("auth.sudo.parameter", "actas");
        Configuration configuration = mock(Configuration.class);
        when(configuration.getProperties()).thenReturn(properties);
        ConfigurationAdmin admin = mock(ConfigurationAdmin.class);
        when(admin.listConfigurations(anyString())).thenAnswer(call ->
                ((String) call.getArgument(0)).contains("engine.impl.auth.SlingAuthenticator") ? new Configuration[] {configuration} : null);
        OboImpersonationGuard guard = guard(admin);
        HttpServletRequest cookie = mock(HttpServletRequest.class);
        when(cookie.getCookies()).thenReturn(new Cookie[] {new Cookie("my.sudo", "Ym9i")});
        assertTrue(guard.impersonationRequested(cookie));
        HttpServletRequest parameter = mock(HttpServletRequest.class);
        when(parameter.getParameter("actas")).thenReturn("bob");
        assertTrue(guard.impersonationRequested(parameter));
        HttpServletRequest defaults = mock(HttpServletRequest.class);
        when(defaults.getParameter("sudo")).thenReturn("bob");
        assertTrue(guard.impersonationRequested(defaults));
    }

    @Test
    void aBrokenConfigurationReadStillAppliesTheDefaults() throws Exception {
        ConfigurationAdmin admin = mock(ConfigurationAdmin.class);
        when(admin.listConfigurations(anyString())).thenThrow(new java.io.IOException("unavailable"));
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("sudo")).thenReturn("bob");
        assertTrue(guard(admin).impersonationRequested(request));
    }

    @Test
    void aResolverThatReportsAnImpersonatorCountsAsImpersonated() throws Exception {
        SlingHttpServletRequest request = mock(SlingHttpServletRequest.class);
        ResourceResolver resolver = mock(ResourceResolver.class);
        when(request.getResourceResolver()).thenReturn(resolver);
        assertFalse(guard(null).impersonated(request));
        when(resolver.getAttribute("user.impersonator")).thenReturn("admin");
        assertTrue(guard(null).impersonated(request));
    }
}
