package com.gradial.core.oauth.scopes.impl;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

import javax.jcr.Repository;
import javax.jcr.Session;
import javax.jcr.SimpleCredentials;
import javax.jcr.Value;
import javax.jcr.security.AccessControlEntry;
import javax.jcr.security.AccessControlPolicy;
import javax.jcr.security.Privilege;

import org.apache.jackrabbit.api.JackrabbitSession;
import org.apache.jackrabbit.api.security.JackrabbitAccessControlEntry;
import org.apache.jackrabbit.api.security.JackrabbitAccessControlList;
import org.apache.jackrabbit.api.security.user.Authorizable;
import org.apache.jackrabbit.api.security.user.User;
import org.apache.jackrabbit.oak.jcr.Jcr;
import org.apache.jackrabbit.oak.security.internal.SecurityProviderBuilder;
import org.apache.jackrabbit.oak.spi.security.ConfigurationParameters;
import org.apache.jackrabbit.oak.spi.security.user.UserConfiguration;
import org.apache.sling.jcr.api.SlingRepository;
import org.apache.sling.jcr.repoinit.impl.JcrRepoInitOpsProcessorImpl;
import org.apache.sling.repoinit.parser.impl.RepoInitParserService;
import org.junit.jupiter.api.Test;

/**
 * The Java setup in {@link ScopeReaderRepositoryInitializer} must leave exactly what Sling's real repoinit leaves
 * for the original {@code gradial-oauth-scopes.repoinit} script (kept in test resources): same user, same path,
 * same ACL entries on /.
 */
class ScopeReaderEquivalenceTest {
    private static Repository newRepository() throws Exception {
        Map<String, Object> paths = new HashMap<>();
        paths.put("usersPath", "/home/users");
        paths.put("groupsPath", "/home/groups");
        return new Jcr().with(SecurityProviderBuilder.newBuilder()
                .with(ConfigurationParameters.of(UserConfiguration.NAME, ConfigurationParameters.of(paths))).build())
                .createRepository();
    }

    private static Session admin(Repository repository) throws Exception {
        return repository.login(new SimpleCredentials("admin", "admin".toCharArray()));
    }

    private static void applyRepoinit(Repository repository) throws Exception {
        Session session = admin(repository);
        try (InputStream in = ScopeReaderEquivalenceTest.class.getResourceAsStream("gradial-oauth-scopes.repoinit");
             Reader script = new InputStreamReader(in, StandardCharsets.UTF_8)) {
            new JcrRepoInitOpsProcessorImpl().apply(session, new RepoInitParserService().parse(script));
            session.save();
        } finally { session.logout(); }
    }

    private static void applyJava(Repository repository) throws Exception {
        SlingRepository sling = mock(SlingRepository.class);
        when(sling.loginAdministrative(null)).thenAnswer(call -> admin(repository));
        assertTrue(new ScopeReaderRepositoryInitializer().apply(sling));
    }

    private static List<String> describe(Repository repository) throws Exception {
        Session session = admin(repository);
        try {
            List<String> out = new ArrayList<>();
            Authorizable user = ((JackrabbitSession) session).getUserManager().getAuthorizable(DynamicScopeRegistrar.READER);
            assertNotNull(user, "user exists");
            out.add("system=" + ((User) user).isSystemUser() + " group=" + user.isGroup());
            out.add("path=" + user.getPath());
            for (AccessControlPolicy policy : session.getAccessControlManager().getPolicies("/")) {
                if (!(policy instanceof JackrabbitAccessControlList)) continue;
                for (AccessControlEntry e : ((JackrabbitAccessControlList) policy).getAccessControlEntries()) {
                    JackrabbitAccessControlEntry entry = (JackrabbitAccessControlEntry) e;
                    if (!DynamicScopeRegistrar.READER.equals(entry.getPrincipal().getName())) continue;
                    TreeSet<String> privileges = new TreeSet<>();
                    for (Privilege p : entry.getPrivileges()) privileges.add(p.getName());
                    List<String> restrictions = new ArrayList<>();
                    for (String name : entry.getRestrictionNames()) {
                        List<String> values = new ArrayList<>();
                        Value single = entry.getRestriction(name);
                        if (single != null) values.add(single.getString());
                        for (Value v : entry.getRestrictions(name)) values.add(v.getString());
                        Collections.sort(values);
                        restrictions.add(name + "=" + values);
                    }
                    Collections.sort(restrictions);
                    out.add("entry privileges=" + privileges + " allow=" + entry.isAllow() + " restrictions=" + restrictions);
                }
            }
            return out;
        } finally { session.logout(); }
    }

    @Test
    void javaSetupMatchesSlingRepoinitOnAFreshRepository() throws Exception {
        Repository viaRepoinit = newRepository();
        Repository viaJava = newRepository();
        applyRepoinit(viaRepoinit);
        applyJava(viaJava);
        List<String> expected = describe(viaRepoinit);
        assertEquals(3, expected.size(), "user flags, path and one ACL entry: " + expected);
        assertTrue(expected.get(1).startsWith("path=/home/users/system/gradial/"), expected.get(1));
        assertEquals(expected, describe(viaJava));
    }

    @Test
    void applyingTheJavaSetupTwiceAddsNoEntry() throws Exception {
        Repository repository = newRepository();
        applyJava(repository);
        List<String> once = describe(repository);
        applyJava(repository);
        applyJava(repository);
        assertEquals(once, describe(repository));
        assertEquals(1, once.stream().filter(l -> l.startsWith("entry ")).count());
    }
}
