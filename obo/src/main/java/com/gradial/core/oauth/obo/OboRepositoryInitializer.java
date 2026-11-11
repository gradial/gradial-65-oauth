package com.gradial.core.oauth.obo;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;

import javax.jcr.Session;

import org.apache.jackrabbit.api.JackrabbitSession;
import org.apache.jackrabbit.api.security.user.Authorizable;
import org.apache.jackrabbit.api.security.user.User;
import org.apache.sling.jcr.api.SlingRepository;
import org.apache.sling.jcr.api.SlingRepositoryInitializer;
import org.apache.sling.jcr.repoinit.JcrRepoInitOpsProcessor;
import org.apache.sling.repoinit.parser.RepoInitParser;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.ConfigurationPolicy;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Sets up the {@value #SERVICE_USER} service user and the delegation store with Sling's repoinit parser and
 * processor, but never from a repoinit configuration: an existing normal user or group with that ID makes
 * {@code create service user} throw, and a throwing configuration-based repoinit stops SlingRepository at
 * startup. This initializer instead leaves such an account untouched, applies nothing, logs one ERROR and never
 * throws, so AEM always starts. Delegation then stays inert: the service mapping refuses a non-system user, so no
 * consent or token request can succeed.
 *
 * <p>Runs only when its configuration exists, which this package ships for Author only.
 */
@Component(service = SlingRepositoryInitializer.class, configurationPolicy = ConfigurationPolicy.REQUIRE)
public class OboRepositoryInitializer implements SlingRepositoryInitializer {
    private static final Logger LOG = LoggerFactory.getLogger(OboRepositoryInitializer.class);
    static final String SERVICE_USER = "gradial-obo-state";
    static final String SCRIPT = "gradial-obo.repoinit";

    @Reference
    private RepoInitParser parser;
    @Reference
    private JcrRepoInitOpsProcessor processor;

    @Override
    public void processRepository(SlingRepository repository) {
        try {
            apply(repository);
        } catch (Exception | LinkageError e) {
            LOG.error("Could not set up user delegation ({}); delegation stays unavailable. AEM starts normally.",
                    SERVICE_USER, e);
        }
    }

    /** True when the script was applied; false when an account of another kind holds the ID. */
    boolean apply(SlingRepository repository) throws Exception {
        // An admin session is what repoinit's own initializer uses for the same statements.
        Session session = repository.loginAdministrative(null);
        try {
            Authorizable existing = ((JackrabbitSession) session).getUserManager().getAuthorizable(SERVICE_USER);
            if (existing != null && (existing.isGroup() || !((User) existing).isSystemUser())) {
                LOG.error("The ID {} already belongs to a {} that is not this package's service user. It was left "
                        + "unchanged and nothing was set up; user delegation stays unavailable. Rename that account to "
                        + "enable it.", SERVICE_USER, existing.isGroup() ? "group" : "user");
                return false;
            }
            try (Reader script = script()) {
                processor.apply(session, parser.parse(script));
            }
            session.save();
            return true;
        } finally {
            session.logout();
        }
    }

    static Reader script() throws IOException {
        InputStream stream = OboRepositoryInitializer.class.getResourceAsStream(SCRIPT);
        if (stream == null) throw new IOException("Missing " + SCRIPT);
        return new InputStreamReader(stream, StandardCharsets.UTF_8);
    }
}
