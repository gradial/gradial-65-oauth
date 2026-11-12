package com.gradial.core.oauth.scopes.impl;

/**
 * Marker service that {@link ScopeReaderRepositoryInitializer} registers once the
 * {@value DynamicScopeRegistrar#READER} service user exists as this package's system user. Each
 * {@link DynamicScopeRegistrar} binds it dynamically and re-checks its path then.
 *
 * <p>Needed because, on a fresh install, the scope configurations and the initializer configuration
 * arrive in the same content package: the registrars can activate before the initializer has created the
 * user, so their first check cannot log in. {@code ServiceUserMapped} alone does not close that gap:
 * Sling's {@code ServiceUserMapperImpl} registers it as soon as the mapping configuration is active,
 * whether or not the user exists yet (serviceusermapper 1.5.8, {@code ServiceUserMapperImpl.java:426-436}).
 *
 * <p>Deliberately free of repoinit types, so registrars load even when repoinit is not installed.
 */
interface ScopeReaderReady {
}
