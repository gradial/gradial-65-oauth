package com.gradial.core.oauth.obo;

import java.security.Principal;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import javax.jcr.Credentials;
import javax.jcr.RepositoryException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import org.apache.felix.jaas.LoginModuleFactory;
import org.apache.jackrabbit.oak.spi.security.authentication.AbstractLoginModule;
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

    static class DelegationLoginModule extends AbstractLoginModule {
        private final OboService service;
        private String userId;
        private Set<Principal> principals = Collections.emptySet();
        private OboCredentials credentials;
        private AuthInfoImpl authInfo;

        DelegationLoginModule(OboService service) { this.service = service; }

        @Override
        @SuppressWarnings("rawtypes")
        protected Set<Class> getSupportedCredentials() {
            return Collections.singleton(OboCredentials.class);
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
                return true;
            } catch (RepositoryException e) {
                // Do not attach the exception: repository errors can contain credential-bearing paths.
                throw new LoginException("Invalid or expired Gradial delegation");
            }
        }

        @Override
        public boolean commit() throws LoginException {
            if (userId == null) return false;
            if (subject.isReadOnly()) throw new LoginException("Read-only authentication subject");
            subject.getPrincipals().addAll(principals);
            subject.getPublicCredentials().add(credentials);
            authInfo = new AuthInfoImpl(userId, Collections.emptyMap(), principals);
            setAuthInfo(authInfo, subject);
            closeSystemSession();
            return true;
        }

        @Override
        public boolean logout() throws LoginException {
            Set<Object> publicCredentials = new HashSet<>();
            if (credentials != null) publicCredentials.add(credentials);
            if (authInfo != null) publicCredentials.add(authInfo);
            boolean result = logout(publicCredentials, principals);
            clearState();
            return result;
        }

        @Override
        protected void clearState() {
            super.clearState();
            userId = null;
            credentials = null;
            authInfo = null;
            principals = Collections.emptySet();
        }
    }
}
