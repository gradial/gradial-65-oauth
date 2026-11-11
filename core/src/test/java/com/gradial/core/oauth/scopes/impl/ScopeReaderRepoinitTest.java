package com.gradial.core.oauth.scopes.impl;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

import javax.jcr.Node;
import javax.jcr.Repository;
import javax.jcr.Session;
import javax.jcr.SimpleCredentials;

import org.apache.jackrabbit.api.JackrabbitSession;
import org.apache.jackrabbit.api.security.user.Authorizable;
import org.apache.jackrabbit.api.security.user.User;
import org.apache.jackrabbit.api.security.user.UserManager;
import org.apache.jackrabbit.oak.jcr.Jcr;
import org.apache.jackrabbit.oak.security.internal.SecurityProviderBuilder;
import org.apache.jackrabbit.oak.spi.security.ConfigurationParameters;
import org.apache.jackrabbit.oak.spi.security.user.UserConfiguration;
import org.apache.sling.jcr.api.SlingRepository;
import org.apache.sling.jcr.repoinit.impl.JcrRepoInitOpsProcessorImpl;
import org.apache.sling.repoinit.parser.impl.RepoInitParserService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Runs {@link ScopeReaderRepositoryInitializer} on real Oak (AEM 6.5 SP25's Oak and repoinit, or 6.5 LTS's on
 * JDK 14+). It must set the service user up when it can, leave any other account with that ID untouched, and
 * never throw: a throwing initializer stops SlingRepository at startup.
 */
class ScopeReaderRepoinitTest {
    private Repository repository;
    private Session admin;
    private SlingRepository sling;
    private ScopeReaderRepositoryInitializer initializer;

    @BeforeEach
    void repository() throws Exception {
        Map<String, Object> paths = new HashMap<>();
        paths.put("usersPath", "/home/users");
        paths.put("groupsPath", "/home/groups");
        repository = new Jcr().with(SecurityProviderBuilder.newBuilder()
                .with(ConfigurationParameters.of(UserConfiguration.NAME, ConfigurationParameters.of(paths))).build())
                .createRepository();
        admin = repository.login(new SimpleCredentials("admin", "admin".toCharArray()));
        users().createUser("zz-seed", null);
        Node site = admin.getRootNode().addNode("content", "nt:unstructured").addNode("site", "nt:unstructured");
        site.setProperty("secret", "value");
        admin.save();
        sling = mock(SlingRepository.class);
        when(sling.loginAdministrative(null)).thenAnswer(call -> repository.login(new SimpleCredentials("admin", "admin".toCharArray())));
        initializer = new ScopeReaderRepositoryInitializer();
        inject("parser", new RepoInitParserService());
        inject("processor", new JcrRepoInitOpsProcessorImpl());
    }

    @AfterEach
    void close() { admin.logout(); }

    private UserManager users() throws Exception { return ((JackrabbitSession) admin).getUserManager(); }

    private void inject(String field, Object value) throws Exception {
        Field f = ScopeReaderRepositoryInitializer.class.getDeclaredField(field);
        f.setAccessible(true);
        f.set(initializer, value);
    }

    @Test
    void setsUpAReaderThatSeesNodesButNoPropertiesAndAppliesTwice() throws Exception {
        assertTrue(initializer.apply(sling));
        assertTrue(initializer.apply(sling));
        admin.refresh(false);
        Authorizable reader = users().getAuthorizable(DynamicScopeRegistrar.READER);
        assertTrue(reader instanceof User && ((User) reader).isSystemUser());
        Session session = admin.impersonate(new SimpleCredentials(DynamicScopeRegistrar.READER, new char[0]));
        try {
            assertTrue(session.nodeExists("/content/site"), "the reader can test that a scope path exists");
            assertFalse(session.nodeExists("/content/missing"));
            assertFalse(session.propertyExists("/content/site/secret"), "the reader cannot read content");
            assertThrows(Exception.class, () -> {
                session.getNode("/content/site").addNode("zz");
                session.save();
            }, "the reader cannot write");
        } finally { session.logout(); }
    }

    @Test
    void aNormalUserWithTheIdIsLeftUntouchedAndNothingIsApplied() throws Exception {
        users().createUser(DynamicScopeRegistrar.READER, "customer-password");
        admin.save();
        String path = users().getAuthorizable(DynamicScopeRegistrar.READER).getPath();
        assertFalse(initializer.apply(sling));
        initializer.processRepository(sling);
        admin.refresh(false);
        Authorizable account = users().getAuthorizable(DynamicScopeRegistrar.READER);
        assertFalse(((User) account).isSystemUser(), "the customer's account is not converted");
        assertEquals(path, account.getPath(), "nor moved or recreated");
        org.apache.jackrabbit.api.security.JackrabbitAccessControlList acl =
                org.apache.jackrabbit.commons.jackrabbit.authorization.AccessControlUtils.getAccessControlList(admin, "/");
        if (acl != null) {
            for (javax.jcr.security.AccessControlEntry entry : acl.getAccessControlEntries()) {
                assertNotEquals(DynamicScopeRegistrar.READER, entry.getPrincipal().getName(), "no ACL was written for it");
            }
        }
        Session customer = repository.login(new SimpleCredentials(DynamicScopeRegistrar.READER, "customer-password".toCharArray()));
        customer.logout();
    }

    @Test
    void aGroupWithTheIdIsLeftUntouchedAndNothingIsApplied() throws Exception {
        users().createGroup(DynamicScopeRegistrar.READER);
        admin.save();
        assertFalse(initializer.apply(sling));
        initializer.processRepository(sling);
        admin.refresh(false);
        assertTrue(users().getAuthorizable(DynamicScopeRegistrar.READER).isGroup());
    }

    @Test
    void anExistingServiceUserIsKeptAndTheAclIsEnsured() throws Exception {
        users().createSystemUser(DynamicScopeRegistrar.READER, "system/gradial");
        admin.save();
        assertTrue(initializer.apply(sling));
        Session session = admin.impersonate(new SimpleCredentials(DynamicScopeRegistrar.READER, new char[0]));
        try { assertTrue(session.nodeExists("/content/site")); } finally { session.logout(); }
    }

    @Test
    void anyFailureIsLoggedAndNeverThrown() throws Exception {
        SlingRepository broken = mock(SlingRepository.class);
        when(broken.loginAdministrative(null)).thenThrow(new javax.jcr.RepositoryException("unavailable"));
        assertDoesNotThrow(() -> initializer.processRepository(broken));
        inject("processor", (org.apache.sling.jcr.repoinit.JcrRepoInitOpsProcessor) (s, ops) -> { throw new RuntimeException("boom"); });
        assertDoesNotThrow(() -> initializer.processRepository(sling));
    }
}
