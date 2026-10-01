package com.gradial.core.oauth.obo;

import java.io.IOException;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Map;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import javax.jcr.Credentials;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.jcr.RepositoryException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import org.apache.felix.jaas.LoginModuleFactory;
import org.apache.jackrabbit.oak.api.AuthInfo;
import org.apache.jackrabbit.oak.api.ContentRepository;
import org.apache.jackrabbit.oak.api.ContentSession;
import org.apache.jackrabbit.oak.namepath.NamePathMapper;
import org.apache.jackrabbit.oak.spi.security.SecurityProvider;
import org.apache.jackrabbit.oak.spi.security.authentication.SystemSubject;
import org.apache.jackrabbit.oak.spi.security.authentication.callback.CredentialsCallback;
import org.apache.jackrabbit.oak.spi.security.authentication.callback.RepositoryCallback;
import org.apache.jackrabbit.oak.spi.security.principal.PrincipalConfiguration;
import org.apache.jackrabbit.oak.spi.security.authentication.AuthInfoImpl;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;

@Component(service = LoginModuleFactory.class,
        property = {"jaas.controlFlag=sufficient", "jaas.ranking:Integer=1000", "jaas.realmName=jackrabbit.oak"})
public class OboLoginModuleFactory implements LoginModuleFactory {
    @Reference
    private OboService service;

    @Override
    public LoginModule createLoginModule() {
        return new DelegationLoginModule(service);
    }

    static class DelegationLoginModule implements LoginModule {
        private final OboService service;
        private Subject subject;
        private CallbackHandler callbackHandler;
        private String userId;
        private boolean authenticated;
        private boolean committed;
        private final Set<Principal> addedPrincipals = new HashSet<>();
        private Set<Principal> principals = Collections.emptySet();
        private OboCredentials credentials;
        private AuthInfoImpl authInfo;

        DelegationLoginModule(OboService service) { this.service = service; }

        @Override
        public void initialize(Subject subject, CallbackHandler callbackHandler,
                Map<String, ?> sharedState, Map<String, ?> options) {
            this.subject = subject;
            this.callbackHandler = callbackHandler;
        }

        protected Credentials getCredentials() throws LoginException {
            if (callbackHandler == null) return null;
            CredentialsCallback callback = new CredentialsCallback();
            try {
                callbackHandler.handle(new Callback[] {callback});
                return callback.getCredentials();
            } catch (IOException | UnsupportedCallbackException e) {
                throw new LoginException("Cannot retrieve authentication credentials");
            }
        }

        protected Set<? extends Principal> getPrincipals(String userId) throws LoginException {
            RepositoryCallback callback = new RepositoryCallback();
            try {
                callbackHandler.handle(new Callback[] {callback});
                ContentRepository repository = callback.getContentRepository();
                SecurityProvider security = callback.getSecurityProvider();
                if (repository == null || security == null) throw new LoginException("Principal lookup unavailable");
                // The system subject is confined to reading membership; it is never the authenticated subject.
                ContentSession session = Subject.doAs(SystemSubject.INSTANCE,
                        (PrivilegedExceptionAction<ContentSession>) () -> repository.login(null, callback.getWorkspaceName()));
                try {
                    return new HashSet<>(security.getConfiguration(PrincipalConfiguration.class)
                            .getPrincipalProvider(session.getLatestRoot(), NamePathMapper.DEFAULT).getPrincipals(userId));
                } finally {
                    session.close();
                }
            } catch (IOException | UnsupportedCallbackException | PrivilegedActionException e) {
                throw new LoginException("Cannot resolve delegated user principals");
            }
        }

        @Override
        public boolean login() throws LoginException {
            Credentials candidate = getCredentials();
            if (!(candidate instanceof OboCredentials)) return false;
            credentials = (OboCredentials) candidate;
            try {
                userId = service.authenticate(credentials.token());
                principals = new HashSet<>(getPrincipals(userId));
                if (principals.isEmpty()) throw new LoginException("Delegated user has no principals");
                authenticated = true;
                return true;
            } catch (RepositoryException e) {
                // Do not attach the exception: repository errors can contain credential-bearing paths.
                throw new LoginException("Invalid or expired Gradial delegation");
            }
        }

        @Override
        public boolean commit() throws LoginException {
            if (!authenticated) return false;
            if (subject.isReadOnly()) throw new LoginException("Read-only authentication subject");
            if (!subject.getPublicCredentials(AuthInfo.class).isEmpty()) {
                throw new LoginException("Authentication subject already has an identity");
            }
            addedPrincipals.addAll(principals);
            addedPrincipals.removeAll(subject.getPrincipals());
            subject.getPrincipals().addAll(addedPrincipals);
            subject.getPublicCredentials().add(credentials);
            authInfo = new AuthInfoImpl(userId, Collections.emptyMap(), principals);
            subject.getPublicCredentials().add(authInfo);
            committed = true;
            return true;
        }

        @Override
        public boolean logout() throws LoginException {
            if (!committed) { clearState(); return false; }
            if (subject.isReadOnly()) throw new LoginException("Read-only authentication subject");
            subject.getPublicCredentials().remove(credentials);
            subject.getPublicCredentials().remove(authInfo);
            subject.getPrincipals().removeAll(addedPrincipals);
            clearState();
            return true;
        }

        @Override
        public boolean abort() throws LoginException {
            boolean result = authenticated;
            if (committed) logout();
            else clearState();
            return result;
        }

        private void clearState() {
            userId = null;
            credentials = null;
            authInfo = null;
            authenticated = false;
            committed = false;
            principals = Collections.emptySet();
            addedPrincipals.clear();
        }
    }
}
