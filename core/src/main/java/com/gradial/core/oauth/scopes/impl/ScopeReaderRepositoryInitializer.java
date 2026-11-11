package com.gradial.core.oauth.scopes.impl;

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
 * Creates the {@value DynamicScopeRegistrar#READER} service user that checks scope paths, with Sling's repoinit
 * parser and processor, but never from a repoinit configuration: an existing normal user or group with that ID
 * makes {@code create service user} throw, and a throwing configuration-based repoinit stops SlingRepository at
 * startup. This initializer instead leaves such an account untouched, applies nothing, logs one ERROR and never
 * throws, so AEM always starts. Scopes then register without the existence check, as before.
 *
 * <p>Runs only when its configuration exists, which this package ships for Author only.
 */
@Component(service = SlingRepositoryInitializer.class, configurationPolicy = ConfigurationPolicy.REQUIRE)
public class ScopeReaderRepositoryInitializer implements SlingRepositoryInitializer {
    private static final Logger LOG = LoggerFactory.getLogger(ScopeReaderRepositoryInitializer.class);
    static final String SCRIPT = "gradial-oauth-scopes.repoinit";

    @Reference
    private RepoInitParser parser;
    @Reference
    private JcrRepoInitOpsProcessor processor;

    @Override
    public void processRepository(SlingRepository repository) {
        try {
            apply(repository);
        } catch (Exception | LinkageError e) {
            LOG.error("Could not set up the {} service user; OAuth scopes register without checking their paths. AEM "
                    + "starts normally.", DynamicScopeRegistrar.READER, e);
        }
    }

    /** True when the script was applied; false when an account of another kind holds the ID. */
    boolean apply(SlingRepository repository) throws Exception {
        // An admin session is what repoinit's own initializer uses for the same statements.
        Session session = repository.loginAdministrative(null);
        try {
            Authorizable existing = ((JackrabbitSession) session).getUserManager().getAuthorizable(DynamicScopeRegistrar.READER);
            if (existing != null && (existing.isGroup() || !((User) existing).isSystemUser())) {
                LOG.error("The ID {} already belongs to a {} that is not this package's service user. It was left "
                        + "unchanged and nothing was set up; OAuth scopes register without checking their paths. Rename "
                        + "that account to enable the check.", DynamicScopeRegistrar.READER, existing.isGroup() ? "group" : "user");
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
        InputStream stream = ScopeReaderRepositoryInitializer.class.getResourceAsStream(SCRIPT);
        if (stream == null) throw new IOException("Missing " + SCRIPT);
        return new InputStreamReader(stream, StandardCharsets.UTF_8);
    }
}
