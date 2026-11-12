package com.gradial.core.oauth.obo;

import java.security.Principal;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.jcr.Credentials;
import javax.jcr.RepositoryException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import org.apache.felix.jaas.LoginModuleFactory;
import org.apache.jackrabbit.api.security.user.Authorizable;
import org.apache.jackrabbit.api.security.user.User;
import org.apache.jackrabbit.api.security.user.UserManager;
import org.apache.jackrabbit.oak.api.PropertyState;
import org.apache.jackrabbit.oak.api.Root;
import org.apache.jackrabbit.oak.api.Tree;
import org.apache.jackrabbit.oak.api.Type;
import org.apache.jackrabbit.oak.spi.security.authentication.AbstractLoginModule;
import org.apache.jackrabbit.oak.spi.security.authentication.AuthInfoImpl;
import org.apache.jackrabbit.util.ISO8601;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;

/**
 * Registers the delegation login module with Oak through Felix JAAS, the same way Oak's own
 * {@code ExternalLoginModuleFactory} does. Present only while a delegation configuration exists.
 */
@Component(service = LoginModuleFactory.class,
        property = {"jaas.controlFlag=sufficient", "jaas.ranking:Integer=1000", "jaas.realmName=jackrabbit.oak"})
public class OboLoginModuleFactory implements LoginModuleFactory {
    /** Session attribute: SHA-256 of the access credential this session was opened with. */
    static final String ACCESS_ATTRIBUTE = "gradial.obo.access";

    @Reference
    private OboService service;

    @Override
    public LoginModule createLoginModule() {
        return new DelegationLoginModule(service);
    }

    /**
     * Validates a {@link OboCredentials} on the module's own system root, as Oak's TokenLoginModule
     * validates login tokens, and resolves the user's principals through Oak's principal provider.
     * This is the only place a delegated request is validated.
     */
    static class DelegationLoginModule extends AbstractLoginModule {
        private static final Set<Class> SUPPORTED = Collections.<Class>singleton(OboCredentials.class);
        private final OboService service;
        private OboCredentials credentials;
        private String userId;
        private Set<? extends Principal> principals;

        DelegationLoginModule(OboService service) { this.service = service; }

        @Override
        protected Set<Class> getSupportedCredentials() { return SUPPORTED; }

        @Override
        public boolean login() throws LoginException {
            Credentials candidate = getCredentials();
            if (!(candidate instanceof OboCredentials)) return false;
            OboCredentials presented = (OboCredentials) candidate;
            Root root = getRoot();
            UserManager users = getUserManager();
            if (root == null || users == null) throw new LoginException("Delegation lookup unavailable");
            try {
                String validated = service.validateAccess(records(root), users, presented.token());
                Set<? extends Principal> resolved = getPrincipals(validated);
                if (resolved == null || resolved.isEmpty()) throw new LoginException("Delegated user has no principals");
                // Authoritative check on the full principal set (nested, overflow and dynamic membership). It runs on
                // every request, so it also covers users who became administrators after consent.
                if (!service.allowAdministrators() && (administrative(resolved) || administrative(users.getAuthorizable(validated)))) {
                    OboAudit.event("delegation_refused", validated, OboService.id(presented.token()), "reason=administrator");
                    throw new LoginException("Administrative accounts cannot use delegation");
                }
                credentials = presented;
                userId = validated;
                principals = resolved;
                return true;
            } catch (RepositoryException e) {
                // Do not attach the exception: it can name a record path that a credential embeds.
                throw new LoginException("Invalid or expired Gradial delegation");
            } finally {
                closeSystemSession();
            }
        }

        /**
         * Membership in {@code administrators}, read from the full resolved principal set (nested, overflow and
         * dynamic membership).
         */
        static boolean administrative(Set<? extends Principal> principals) {
            for (Principal principal : principals) {
                if ("administrators".equals(principal.getName())) return true;
            }
            return false;
        }

        /**
         * The admin user, or a system (service) user. Read through Jackrabbit's user API rather than Oak's
         * {@code org.apache.jackrabbit.oak.spi.security.principal} classes ({@code AdminPrincipal},
         * {@code SystemUserPrincipal}): that package is exported at 1.8 by AEM 6.5 and at 2.1.1 by AEM 6.5 LTS
         * (oak-security-spi 1.88.0), so no single import range covers both. {@code SystemPrincipal} belongs only to
         * Oak's internal system subject, which a delegated login can never carry.
         */
        static boolean administrative(Authorizable authorizable) throws RepositoryException {
            if (!(authorizable instanceof User)) return authorizable != null;
            User user = (User) authorizable;
            return user.isAdmin() || user.isSystemUser();
        }

        @Override
        public boolean commit() throws LoginException {
            if (credentials == null) {
                clearState();
                return false;
            }
            if (subject.isReadOnly()) throw new LoginException("Read-only authentication subject");
            if (!subject.getPublicCredentials(org.apache.jackrabbit.oak.api.AuthInfo.class).isEmpty()) {
                throw new LoginException("Authentication subject already has an identity");
            }
            Map<String, Object> attributes = new HashMap<>();
            attributes.put(ACCESS_ATTRIBUTE, OboService.hash(credentials.token()));
            subject.getPrincipals().addAll(principals);
            subject.getPublicCredentials().add(credentials);
            setAuthInfo(new AuthInfoImpl(userId, attributes, new HashSet<Principal>(principals)), subject);
            return true;
        }

        @Override
        public boolean logout() throws LoginException {
            if (credentials == null) return false;
            if (!subject.isReadOnly()) {
                // Remove only what this module added; other modules' principals and credentials stay.
                subject.getPublicCredentials().remove(credentials);
                subject.getPublicCredentials().removeAll(subject.getPublicCredentials(org.apache.jackrabbit.oak.api.AuthInfo.class));
                subject.getPrincipals().removeAll(principals);
            }
            clearState();
            return true;
        }

        @Override
        protected void clearState() {
            super.clearState();
            credentials = null;
            userId = null;
            principals = null;
        }
    }

    /** Grant and user records read from the login module's system root. */
    static OboService.Records records(Root root) {
        return path -> {
            Tree tree = root.getTree(path);
            if (!tree.exists()) return null;
            return new OboService.Record() {
                @Override public String identifier() { return string("jcr:uuid"); }
                @Override public String string(String name) {
                    PropertyState property = tree.getProperty(name);
                    return property == null || property.isArray() ? null : property.getValue(Type.STRING);
                }
                @Override public long number(String name, long absent) {
                    PropertyState property = tree.getProperty(name);
                    return property == null || property.isArray() ? absent : property.getValue(Type.LONG);
                }
                @Override public boolean flag(String name) {
                    PropertyState property = tree.getProperty(name);
                    return property != null && !property.isArray() && property.getValue(Type.BOOLEAN);
                }
                @Override public long date(String name) {
                    PropertyState property = tree.getProperty(name);
                    if (property == null || property.isArray()) return -1;
                    java.util.Calendar value = ISO8601.parse(property.getValue(Type.DATE));
                    return value == null ? -1 : value.getTimeInMillis();
                }
            };
        };
    }
}
