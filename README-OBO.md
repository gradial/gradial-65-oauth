# User-scoped AEM delegation (opt-in)

This extension uses the ordinary AEM user's repository session for existing Author HTTP APIs. AEM enforces that user's current permissions and records that user as the modifying actor. Existing DynamicScope/Granite OAuth connections remain independent.

This is the AEM side of ENG-4998. Gradial still needs the per-user connection, callback, refresh coordination and authentication picker inside its existing regular AEM integration. This package does not add that UI or claim compatibility with every AEM version.

## Enable on Author

Upgrade the existing `io.github.gradial:gradial.all` package through the customer's deployment pipeline. No delegation services are enabled until an explicit customer configuration is supplied. Deploy on Author only.

Add `com.gradial.core.oauth.obo.OboService.cfg.json` to your project's `config.author`:

```json
{
  "enabled": true,
  "clientId": "gradial",
  "clientSecretSha256": "<SHA-256 of a random confidential-client secret: 64 lowercase hex characters>",
  "redirectUris": ["https://your-gradial-host.example/api/integrations/aem/callback"],
  "publicOrigin": "https://your-author.example",
  "accessTokenSeconds": 300,
  "grantSeconds": 2592000
}
```

The callback illustrates the protocol; it is not an implemented Gradial route. Register the actual callback when Gradial is wired. Match callbacks exactly. Remote callbacks/origins must use HTTPS; HTTP is allowed only for loopback development. `publicOrigin` has no path or trailing slash and matches the browser's Origin header. Keep the random client secret in Gradial's encrypted credential storage; the package stores only its hash. Never use a user's password as the client secret.

The Author configuration creates `gradial-obo-state` and maps `gradial.core:obo`. This service user manages `/var/gradial/obo` and reads user records to reject deleted, disabled and system users. Ordinary users cannot read the delegation store. The state service user has no content-write permission. Review these ACLs against the deployment's existing permissions.

Allow `/bin/gradial/obo/authorize`, `/bin/gradial/obo/token` and `/bin/gradial/obo/revoke` through Author proxies. Token/revocation requests use form-encoded POST and confidential-client authentication. Keep credentials out of logs. Do not exclude authorization from AEM CSRF protection.

## Connect

1. Gradial generates OAuth state and a PKCE verifier, binds them to its initiating user and redirects to `/bin/gradial/obo/authorize` with `response_type=code`, `client_id`, exact `redirect_uri`, `state`, `code_challenge` and `code_challenge_method=S256`.
2. The user signs into AEM through its existing login. Consent displays the authenticated identity and requires Connect. AEM supplies normal CSRF protection; a separate one-use consent nonce is bound to the same user. An existing delegated credential cannot authorize another grant.
3. The callback receives `code` and `state`, or `error=access_denied`. Gradial verifies its retained state and initiating user before exchanging the code. No caller-supplied username is accepted.
4. POST `/bin/gradial/obo/token` with `grant_type=authorization_code`, `code`, `redirect_uri` and `code_verifier`. Authenticate with HTTP Basic (URL-encode ID/secret before Base64), or with form fields `client_id` and `client_secret`. Do not combine methods.

The response contains `access_token`, `refresh_token`, `token_type=GradialOBO` and `expires_in`. Call existing legacy APIs with:

```http
Authorization: GradialOBO <access_token>
```

Obtain/send AEM's CSRF token for mutations as usual. The distinct scheme separates this flow from Adobe IMS and Granite Bearer authentication. Existing handlers keep their behavior. Invalid delegation cannot fall back to a browser cookie or service account.

The Oak login module validates the opaque credential and establishes the original user's identity and principals. AEM checks content permissions and sets audit properties through that ordinary session. The state service user never performs content operations. The implementation does not accept caller-selected impersonation or rewrite modifying-user properties.

## Renewal and disconnect

- POST `grant_type=refresh_token` and `refresh_token` with client authentication. Gradial must serialize refresh per connection. A refresh rotates both credentials and invalidates old access. Replaying a consumed refresh credential revokes the family; reconnect instead of falling back to a service account.
- Access lifetime is 30–3600 seconds. The grant has an absolute lifetime of at most 30 days; refresh does not extend it. The user must sign into AEM and approve again afterward. External identity-provider session expiry is separate from this explicit delegation lifetime.
- POST `token` to `/bin/gradial/obo/revoke` with client authentication. Either current credential revokes the family. Unknown credentials return 200 without revealing grant existence. Verify subsequent access and refresh fail; 200 alone is insufficient.
- Deleted/disabled AEM users cannot access or renew. Grants bind the user node identifier and protected creation timestamp so a recreated username cannot inherit old credentials. AEM permission changes affect new repository sessions. Browser logout is separate from disconnecting Gradial. IMS product-profile removal and synchronization require a separate Cloud lifecycle proof.
- Client, secret, callback or trusted-origin changes invalidate existing grants. Disabling the service blocks delegation. Hourly cleanup removes at most 1,000 expired records per pass, advancing through the grant nodes; traversal cost grows with the stored grant count. Raw access/refresh/consent credentials are not persisted; records contain cryptographic hashes.

Queued Gradial operations must retain the initiating user, and permission-sensitive caches must stay isolated. The package cannot provide those application-level guarantees by itself.

## Compatibility and validation

The implementation targets Java 11 and the existing AEM 6.5 API baseline, using Sling AuthenticationHandler, Felix JAAS LoginModuleFactory and Oak authentication extension points. Compilation does not establish runtime compatibility. AEM Cloud requires deployment through the customer's Cloud Manager pipeline; SDK success alone does not prove Cloud routing or IMS lifecycle behavior.

For each supported deployment, prove ordinary-user identity; allowed/denied reads and writes; real creator/modifier properties; permission changes; disabled/deleted users; renewal after expiry; single-use codes and refresh; effective revocation; concurrent refresh behavior. Inspect denied paths as administrator to confirm no content was created.

Unit tests cover user/consent binding, exact callbacks/PKCE, code replay, rotation/replay revocation, expiry, disabled/deleted users, client authentication, JAAS identity and existing-handler compatibility. Live results belong in PR evidence. Keep incomplete deployments explicitly unverified.
