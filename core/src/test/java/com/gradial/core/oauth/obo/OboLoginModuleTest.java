package com.gradial.core.oauth.obo;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.security.Principal;
import java.util.Collections;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;

import org.apache.jackrabbit.oak.api.AuthInfo;
import org.apache.jackrabbit.oak.api.ContentRepository;
import org.apache.jackrabbit.oak.api.ContentSession;
import org.apache.jackrabbit.oak.api.Root;
import org.apache.jackrabbit.oak.namepath.NamePathMapper;
import org.apache.jackrabbit.oak.spi.security.SecurityProvider;
import org.apache.jackrabbit.oak.spi.security.authentication.SystemSubject;
import org.apache.jackrabbit.oak.spi.security.authentication.callback.CredentialsCallback;
import org.apache.jackrabbit.oak.spi.security.authentication.callback.RepositoryCallback;
import org.apache.jackrabbit.oak.spi.security.principal.PrincipalConfiguration;
import org.apache.jackrabbit.oak.spi.security.principal.PrincipalProvider;
import org.junit.jupiter.api.Test;

class OboLoginModuleTest {
    @Test
    void callbacksResolveOrdinaryUserAndGroupMembershipWithoutLeakingSystemIdentity() throws Exception {
        OboService service = mock(OboService.class);
        when(service.authenticate("token")).thenReturn("writer");
        Principal writer = () -> "writer";
        Principal group = () -> "restricted-authors";
        ContentRepository repository = mock(ContentRepository.class);
        ContentSession session = mock(ContentSession.class);
        Root root = mock(Root.class);
        when(repository.login(null, "default")).thenReturn(session);
        when(session.getLatestRoot()).thenReturn(root);
        SecurityProvider security = mock(SecurityProvider.class);
        PrincipalConfiguration configuration = mock(PrincipalConfiguration.class);
        PrincipalProvider provider = mock(PrincipalProvider.class);
        when(security.getConfiguration(PrincipalConfiguration.class)).thenReturn(configuration);
        when(configuration.getPrincipalProvider(root, NamePathMapper.DEFAULT)).thenReturn(provider);
        doReturn(Set.of(writer, group)).when(provider).getPrincipals("writer");
        CallbackHandler callbacks = values -> {
            for (var callback : values) {
                if (callback instanceof CredentialsCallback) {
                    ((CredentialsCallback) callback).setCredentials(new OboCredentials("token"));
                } else if (callback instanceof RepositoryCallback) {
                    RepositoryCallback target = (RepositoryCallback) callback;
                    target.setContentRepository(repository);
                    target.setSecurityProvider(security);
                    target.setWorkspaceName("default");
                } else throw new UnsupportedCallbackException(callback);
            }
        };
        Subject subject = new Subject();
        subject.getPrincipals().add(group);
        OboLoginModuleFactory.DelegationLoginModule module = new OboLoginModuleFactory.DelegationLoginModule(service);
        module.initialize(subject, callbacks, Collections.emptyMap(), Collections.emptyMap());
        assertTrue(module.login());
        verify(session).close();
        assertTrue(module.commit());
        assertEquals(Set.of(writer, group), subject.getPrincipals());
        assertTrue(Collections.disjoint(subject.getPrincipals(), SystemSubject.INSTANCE.getPrincipals()));
        assertEquals("writer", subject.getPublicCredentials(AuthInfo.class).iterator().next().getUserID());
        assertTrue(module.abort());
        assertEquals(Set.of(group), subject.getPrincipals());
        assertTrue(subject.getPublicCredentials().isEmpty());
        assertFalse(module.commit());
    }

    @Test
    void unavailablePrincipalLookupFailsBeforeChangingAuthenticationSubject() throws Exception {
        OboService service = mock(OboService.class);
        when(service.authenticate("token")).thenReturn("writer");
        Subject subject = new Subject();
        OboLoginModuleFactory.DelegationLoginModule module = new OboLoginModuleFactory.DelegationLoginModule(service);
        module.initialize(subject, values -> {
            for (var callback : values) {
                if (callback instanceof CredentialsCallback) ((CredentialsCallback) callback).setCredentials(new OboCredentials("token"));
                else if (!(callback instanceof RepositoryCallback)) throw new UnsupportedCallbackException(callback);
            }
        }, Collections.emptyMap(), Collections.emptyMap());
        assertThrows(LoginException.class, module::login);
        module.abort();
        assertTrue(subject.getPrincipals().isEmpty());
        assertTrue(subject.getPublicCredentials().isEmpty());
        assertFalse(module.commit());
    }
}
