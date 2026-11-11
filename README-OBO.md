# User-scoped AEM delegation (opt-in)

This extension uses the ordinary AEM user's repository session for existing Author HTTP APIs. AEM enforces that user's current permissions and records that user as the modifying actor. Existing DynamicScope/Granite OAuth connections remain independent.

This is the AEM side of ENG-4998 and ENG-9393. The matching Gradial change adds **Connect AEM** alongside the existing connection. Keep the existing connection ID, OAuth authentication mode, client credentials and network settings. The separate OBO client does not replace them.

## Why not Granite OAuth

AEM's Granite OAuth server (`com.adobe.granite.oauth.server`, marked deprecated in its own component descriptions on 6.5 SP25 and 6.5 LTS) supports the authorization-code grant, consent, refresh and revocation, but a Granite token does not act as the consenting user. Each token becomes a transient `oauth-*` user, a member only of `everyone`, that receives each granted scope's privileges at the scope's single `resourcePath`. The user's own ACLs do not limit it, and repository writes record the synthetic user. Scopes can only allow, one path each. This extension provides what Granite OAuth cannot: the request runs as the user, with the user's principals.

It is built from the platform's own extension points: a Sling `AuthenticationHandler` extracts the credential, an Oak `AbstractLoginModule` (registered through Felix JAAS, as Oak's own external login module is) validates it on its system root and resolves the user's principals through Oak's principal provider, repoinit and a service-user mapping amendment create the store, the Sling scheduler runs cleanup, and Granite CSRF protects consent.

## Requirements

| | Supported | Notes |
|---|---|---|
| AEM 6.5 | SP8 and later | The bundle imports the package versions of the 6.5.8 API. On SP0-SP7 it stays **Installed** (unresolved); nothing registers. Untested below SP25. |
| AEM 6.5 LTS | Yes | Tested on 6.5 LTS (Oak 1.88). |
| Java | 8, 11, 17, 21 | Compiled as Java 8 bytecode (`osgi.ee` JavaSE 1.8; all classes major version 52), so it resolves on every Java that AEM 6.5 and 6.5 LTS run on. Runtime-tested on 11, 17 and 21; Java 8 at runtime is not tested. |
| Run mode | Author only | The bundle installs from `install.author`, and its configurations live in `config.author`. Nothing from this extension installs on Publish. |
| AEM as a Cloud Service | Not verified | See below. |

The legacy `gradial.core` bundle (DynamicScope) is unchanged and is compiled for Java 11, as in released 1.2.0.

## Enable on Author

Deploy the separate `io.github.gradial:gradial.obo` bundle and its two foundation configurations through the customer's existing AEM deployment pipeline, on Author only. The current candidate is `1.2.2-SNAPSHOT`; customer rollout requires the matching reviewed, published immutable artifact. There is no need to replace the legacy OAuth bundle or change its scope configuration. No delegation services are enabled until an explicit customer configuration is supplied.

Add `com.gradial.core.oauth.obo.OboService.cfg.json` to your own project's `config.author` (not under `/apps/gradial`):

```json
{
  "enabled": true,
  "clientId": "gradial",
  "clientSecretSha256": "<SHA-256 of a random confidential-client secret: 64 lowercase hex characters>",
  "redirectUris": ["https://app.gradial.com/api/integrations/aem-obo/callback"],
  "publicOrigin": "https://your-author.example",
  "accessTokenSeconds": 300,
  "grantSeconds": 2592000
}
```

- **Callback.** Gradial production uses `https://app.gradial.com/api/integrations/aem-obo/callback`. A dedicated Gradial host uses `https://<host>/api/integrations/aem-obo/callback`. Callbacks match exactly. Remote callbacks and origins must use HTTPS; HTTP is allowed only for loopback development.
- **Secret.** Generate at least 32 random bytes (for example `openssl rand -base64 32`), keep the raw value in Gradial's encrypted credential storage, and put only its SHA-256 in the configuration. The package cannot measure the secret's entropy from its hash. Never use a user's password. Because only a hash is stored, Granite CryptoSupport is not needed.
- **Origin.** `publicOrigin` has no path or trailing slash and matches the Author origin users open in their browser.
- **Administrators.** Optional `"allowAdministrators": true` lets `admin` and members of `administrators` connect. Leave it off: delegation hands the connected user's principals to Gradial, and for an administrator that bypasses every ACL. With it off, such users cannot consent, and a grant held by a user who later becomes an administrator stops authenticating on the next request.
- **Denied paths.** Optional `deniedPaths` (see [Denied paths](#denied-paths)).

Which changes end existing grants: changing `clientId` or the client secret ends every grant (use this as a kill switch). Changing callbacks, `publicOrigin` or `accessTokenSeconds` does not. Lowering `grantSeconds` shortens live grants; raising it never extends one.

The Author configuration creates `gradial-obo-state` and maps `gradial.obo:obo` to it. This service user manages `/var/gradial/obo` and reads only `rep:User`, `rep:AuthorizableFolder`, `rep:Group` and group member-reference (`rep:MemberReferencesList`, `rep:MemberReferences`) nodes under `/home`, to reject deleted, disabled, system and administrator users and to bind a grant to one account. Password hashes (`rep:password`) are explicitly denied; profiles, preferences, password history and login tokens are outside the node types it may read. The state service user has no content-write permission. `everyone` is denied read and write on `/var/gradial/obo`; `administrators` keep access so they can inspect or delete grants.

Allow `/bin/gradial/obo/authorize`, `/bin/gradial/obo/token` and `/bin/gradial/obo/revoke` through Author proxies. Token and revocation requests use form-encoded POST and confidential-client authentication. Do not exclude authorization from AEM CSRF protection.

In Gradial, open the existing AEM integration's **General** settings. Under **Per-user AEM sign-in**, enter the OBO client ID, its raw random secret and the browser's **AEM sign-in origin**, then choose **Enable per-user sign-in**. Each person chooses **Connect AEM**, signs into their own ordinary AEM account using the existing login or SSO, and approves the displayed identity. A person who has not connected cannot use the protected integration through the service account.

## Install, upgrade and uninstall

What the packages write, and nothing else:

| Package | Filter | Effect |
|---|---|---|
| `gradial.all` | `/apps/gradial-packages`, `/apps/gradial-vendor-packages` (replace) | Holds the bundles and sub-packages. These roots belong to this project. |
| `gradial.ui.apps` | `/apps/gradial-ui-apps-noop` (merge) | Ships no content and changes nothing. Released 1.0.0–1.2.0 used `/apps/gradial` in replace mode, which deleted everything under `/apps/gradial` on every install; see the upgrade note below. |
| `gradial.ui.config` | One `update` root per shipped file under `/apps/gradial/osgiconfig/config*` | Writes exactly the shipped configuration files. Other files in the same folders, and everything else under `/apps/gradial`, are untouched. |
| `gradial.obo` bundle | `install.author` | OSGi bundle on Author. |

Repository setup (Author only) is done by the bundle's repository initializer, which runs once when the bundle starts and at every startup. It applies these Sling repoinit statements with Sling's own repoinit parser and processor, but never from a repoinit configuration. A failing configuration-based repoinit stops SlingRepository at startup; this initializer never throws, so AEM always starts. If a normal user or a group named `gradial-obo-state` already exists, it leaves that account untouched, applies nothing and logs one ERROR. Delegation then stays unavailable: Sling's service mapping refuses a non-system user, so no consent or token request succeeds. Every statement is idempotent and applies over any existing `/var/gradial` (`nt:folder`, `sling:Folder`, `sling:OrderedFolder`, `nt:unstructured`, `oak:Unstructured`, or the pre-release layout). The tests verify this on the AEM 6.5 SP25 and 6.5 LTS Oak and repoinit versions.

```
create service user gradial-obo-state with path system/gradial
create path (sling:Folder) /var/gradial/obo/grants
create path (sling:Folder) /var/gradial/obo/consents
set ACL for everyone: deny jcr:read,rep:write on /var/gradial/obo
set ACL for administrators: allow jcr:read,rep:write on /var/gradial/obo
set ACL for gradial-obo-state: allow jcr:read,rep:write on /var/gradial/obo;
  read /home/users (rep:AuthorizableFolder, rep:User), deny rep:password;
  read /home/groups (rep:AuthorizableFolder, rep:Group, rep:MemberReferencesList, rep:MemberReferences)
```

`create path` leaves existing nodes and their types alone. Nothing under `/content`, `/conf`, `/libs` or `/etc` is written, and under `/home` only the service user and the ACL entries above are added.

When the extension is not configured (no `OboService` configuration, or `enabled: false`), the service user, its ACL entries and the empty `/var/gradial/obo` folders exist but do nothing: a system user cannot sign in, no code uses the mapping, and the authentication handler only reacts to the `GradialOBO` scheme, which it then refuses. That is the standard AEM pattern (repoinit and service users ship with the code), and it keeps install order irrelevant. If the bundle cannot resolve (an AEM below SP8), the same holds.

**Upgrading from 1.0.0–1.2.0.** Those releases' `ui.apps` filtered `/apps/gradial` in replace mode, and `ui.config` replaced `/apps/gradial/osgiconfig`. If an application in the same instance also uses `/apps/gradial` (for example a site named "gradial"), installing an old release removed it. Measured on AEM 6.5 LTS: installing released 1.2.0 `ui.apps` deleted all 3,540 nodes under `/apps/gradial` (another application's components and clientlibs, plus the OBO configurations there), and 1.2.0 `ui.config` then re-created only its own 26 nodes. Installing this version never removes anything under `/apps/gradial`; it updates the old packages in place. Before upgrading an instance where `/apps/gradial` has other content, check that an old release has not already removed it, and restore it from a backup if it has.

**Upgrading from a pre-release OBO build.** Grants and consents from pre-release builds use an older store layout and token format. They stop working on upgrade (users reconnect), and cleanup removes their records. Any ACL entries an earlier build added stay until removed by hand.

**Uninstalling.** Remove the `OboService` configuration first: every grant stops working immediately. Then uninstall `gradial.all` in Package Manager. Uninstall reverts the last install: measured on AEM 6.5 LTS, uninstalling over an upgrade restored the previous release's bundles and sub-packages, the Sling installer uninstalled this release's `ui.config` (removing the OBO and audit configuration files and restoring the earlier scope files), this release's OBO jar was removed (on that instance another package's copy of the same bundle then took over), and nothing outside the packages' filters (customer nodes under `/apps/gradial`, `/apps/gradial/osgiconfig` and `/var/gradial`) was touched. AEM restarted cleanly afterwards. Repoinit content is not removed by uninstall (Sling has no reverse repoinit). To remove it, as an administrator delete `/var/gradial/obo`, the `gradial-obo-state` user and its ACL entries on `/home/users` and `/home/groups`, and the `everyone` and `administrators` entries on `/var/gradial/obo` (which go with the node).

Earlier builds shipped this setup as `org.apache.sling.jcr.repoinit.RepositoryInitializer~gradial-obo.cfg.json`. This version deletes that one file on upgrade, using an exact-file filter root in replace mode. Users and ACLs it already created stay, and the initializer re-applies over them without change.

**Do not ship a second copy of these configurations.** The service-mapping configuration has a fixed PID (`org.apache.sling.serviceusermapping.impl.ServiceUserMapperImpl.amended~gradial-obo`), and older copies of the repoinit configuration may exist in other packages. If another package also ships a file with the same PID (a copy in your own project or a demo package), the Sling installer applies only one of them, and it may be the older one. Measured on AEM 6.5 LTS: an older copy shipped by another package won, so this release's repoinit never ran. Use either this package or your own copies, not both. If you copy them, copy them again on every upgrade.

### Install safety by environment

| Environment | What installs | What could go wrong, and why it does not |
|---|---|---|
| AEM 6.5 SP8+ (Java 8 or 11) | Bundle, configurations, repoinit | Repoinit cannot fail on existing state (tested on SP25's Oak 1.22.24 and repoinit 1.1.38). The bundle resolves on Java 8 and 11. |
| AEM 6.5 SP0–SP7 | Configurations, repoinit; bundle stays Installed | The bundle does not resolve. The OSGi console shows it as Installed; nothing activates. Not tested live. |
| AEM 6.5 LTS (Java 17 or 21) | Bundle, configurations, repoinit | Tested on Oak 1.88 and repoinit 1.1.54. |
| Clustered Author (MongoMK) | As above | Cleanup runs on the leader only. See [Clustered Author](#clustered-author). |
| AMS / on-premise | As above | Deploy through the normal code pipeline. Do not hand-edit `/apps/gradial/osgiconfig`; ship your `OboService` configuration in your own project. |
| Publish | Nothing from this extension | `install.author` and `config.author` only. The legacy `gradial.core` bundle installs on all run modes as before; its DynamicScope components need configurations that exist only in `config.author`, so nothing activates on Publish. |
| Existing `/apps/gradial` content | Only the shipped configuration files | Per-file `update` filters; nothing else under `/apps/gradial` is replaced or removed. |
| Existing `/var/gradial` (any type) | `obo`, `grants`, `consents` as `sling:Folder` if missing | Existing nodes keep their type and content. |
| Existing `/conf`, `/content`, `/etc` | Nothing | Not covered by any filter or repoinit statement. |
| Uninstall | Packages removed | Customer content was never covered, so uninstall cannot remove it. Repoinit content stays; see above. |

## Denied paths

A delegated session carries the user's whole AEM authority, but Gradial needs only content APIs. Delegated requests to these paths are refused with 403, even for a user who could use them in a browser. Each entry covers the path, its descendants and its selector or extension forms. Matching is case-insensitive, on the decoded and normalized request path (checked before login, so it covers non-Sling contexts such as the Web Console) and on the resolved resource path (so `/etc/map` aliases are covered).

- Always refused, cannot be configured away: `/bin/gradial/obo`, `/oauth`, `/libs/granite/oauth`. These mint or manage credentials, for example a Granite OAuth grant that would survive disconnecting Gradial.
- Default `deniedPaths`: `/crx`, `/system`, `/etc/packages`, `/libs/granite/security`, `/libs/cq/security`, `/libs/granite/operations`, `/libs/granite/backup`, `/libs/granite/cluster`, `/libs/granite/distribution`, `/etc/cloudservices`, and for non-GET methods only (`write:` prefix) `/home` and `/etc/replication`.
- Always readable with GET or HEAD: `/libs/granite/security/currentuser`, `whoami` and `userinfo`, and `/libs/cq/security/userinfo`, which Gradial uses to confirm who it acts as.

For Sling POST requests the check also covers every other path the request can act on: `:applyTo` items (absolute, relative, or with a trailing `/*`), `:dest`, absolute and relative property names (for example `/etc/x/prop` or `../../home/...`), and `@MoveFrom` / `@CopyFrom` sources. Ordinary property values are not treated as targets, so a page can still store a path such as `cq:cloudserviceconfigs=/etc/cloudservices/...`. Other POST servlets that take a target path in a parameter value (WCM commands, replication) are bounded by the user's own ACLs, as in AEM itself.

Setting `deniedPaths` replaces the defaults (the always-refused list still applies).

## AEM as a Cloud Service deployment

Cloud runtime and IMS entitlement revocation have not yet been verified for this extension. Adobe's [Author authentication matrix](https://experienceleague.adobe.com/en/docs/experience-manager-learn/cloud-service/authentication/authentication) does not list OAuth as a supported Author option. A successful custom-module test would establish runtime behavior, but would not by itself establish Adobe support. Resolve these questions before customer rollout.

For the package-based candidate, an AEM developer must:

1. Include the separate OBO-capable `io.github.gradial:gradial.obo` bundle in the existing project's Author install location. The current candidate is `1.2.2-SNAPSHOT`, not a verified published Cloud release.
2. Put the supplied `org.apache.sling.serviceusermapping.impl.ServiceUserMapperImpl.amended~gradial-obo.cfg.json` and `org.apache.sling.jcr.repoinit.RepositoryInitializer~gradial-obo.cfg.json` under that project's `config.author`. Keep the filters limited to those configurations and the bundle; do not replace unrelated `/apps/gradial` code.
3. Add the `OboService` configuration above with a dedicated client, trusted Author origin and exact callback. This client belongs to this package; it is not an Adobe Developer Console OAuth Web App registration.
4. Commit and deploy through the customer's existing Cloud Manager code pipeline. [Cloud Package Manager](https://experienceleague.adobe.com/en/docs/experience-manager-cloud-service/content/implementing/developer-tools/package-manager) cannot deploy this Java code.
5. Verify the bundle and foundation services, then test with an IMS-backed non-admin user whose normal Author product profile and content permissions are already configured.
6. Once the matching Gradial release is available, enable **Per-user AEM sign-in** on the existing regular AEM integration.

For development only, an [RDE](https://experienceleague.adobe.com/en/docs/experience-manager-cloud-service/content/implementing/developing/rapid-development-environments) accepts direct bundle and OSGi configuration installation. RDE success must be followed by validation in a normal Cloud development environment.

## Connect

1. Gradial generates OAuth state and a PKCE verifier, binds them to its initiating user and redirects to `/bin/gradial/obo/authorize` with `response_type=code`, `client_id`, exact `redirect_uri`, `state`, `code_challenge` and `code_challenge_method=S256`.
2. The user signs into AEM through its existing login. Consent displays the authenticated identity and requires Connect. AEM supplies normal CSRF protection; a separate one-use consent nonce is bound to the same user. Consent is refused (GET and POST) for a session that is impersonating someone else: any Sling sudo cookie or parameter (the names configured in Sling's authenticator are honored, plus `sling.sudo` and `sudo`) or a resolver that reports an impersonator. An existing delegated credential cannot authorize another grant. `admin` and `administrators` members are refused unless `allowAdministrators` is set. Each user can hold at most five pending consents and ten grants; opening more evicts the oldest.
3. The callback receives `code` and `state`, or `error=access_denied`. Gradial verifies its retained state and initiating user before exchanging the code.
4. POST `/bin/gradial/obo/token` with `grant_type=authorization_code`, `code`, `redirect_uri` and `code_verifier`. Authenticate with HTTP Basic (URL-encode ID and secret before Base64; the scheme name is case-insensitive), or with form fields `client_id` and `client_secret`. Do not combine methods.

**Authorization errors** follow RFC 6749 §4.1.2.1. Every error carries an `error_description` that names the cause without revealing configuration, and AEM logs one WARN with the reason (never a credential or the `state`).

- If `client_id` is not this deployment's client, or `redirect_uri` is not registered exactly, AEM never redirects: it answers on the page with `{"error":"invalid_request","error_description":"client_id is not the one configured on this AEM"}` (or `"redirect_uri is not registered"`). If delegation is disabled, it answers `temporarily_unavailable` the same way.
- Otherwise AEM redirects to the registered `redirect_uri` with `error`, `error_description` and the request's `state`, so the client's sign-in window ends the attempt:

| Cause | `error` | `error_description` |
|---|---|---|
| `response_type` is not `code` | `unsupported_response_type` | response_type must be code |
| PKCE missing, or not S256 | `invalid_request` | PKCE S256 required |
| `state` missing or invalid | `invalid_request` | state is missing or invalid |
| An administrator is signed in (`allowAdministrators` off) | `access_denied` | administrators can't connect; sign in to AEM as your own user |
| The session is impersonating another user | `access_denied` | stop impersonating another user in AEM, then connect as yourself |
| A disabled, system or anonymous account | `access_denied` | this AEM account can't connect |
| The user chose Cancel | `access_denied` | the user declined the connection |

- When the consent page is submitted after it expired (or from another origin), AEM has no trusted callback for it and answers on the page: `sign-in expired, start again`.

The response contains `access_token`, `refresh_token`, `token_type=GradialOBO` and `expires_in`. Call existing APIs with:

```http
Authorization: GradialOBO <access_token>
```

Obtain and send AEM's CSRF token for mutations as usual. Send no AEM cookies with delegated requests.

How a request is authenticated: the authentication handler only wraps the credential. The Oak login module validates it once, on its own system root, then resolves the user's principals (including nested groups and large groups' overflow member lists) and refuses administrative principals. It stamps the session with a hash of the credential. The authentication handler's success callback and a request filter accept the request only if the session carries that stamp, so a cookie handler or a sudo switch cannot substitute another session. Invalid delegation never falls back to a browser cookie or a service account. AEM checks content permissions and sets audit properties through that ordinary session.

## Renewal and disconnect

- POST `grant_type=refresh_token` and `refresh_token` with client authentication. Gradial must serialize refresh per connection. A refresh rotates both credentials and invalidates old access. Replaying one of the last 16 consumed refresh credentials revokes the family; reconnect instead of falling back to a service account.
- Access lifetime is 30–3600 seconds. The grant has an absolute lifetime of at most 30 days; refresh does not extend it.
- POST `token` to `/bin/gradial/obo/revoke` with client authentication. The current access or refresh credential, or a recently consumed refresh credential, revokes the family. Unknown credentials return 200 without revealing grant existence. Verify that later access and refresh fail; 200 alone is insufficient.
- Reusing an authorization code revokes the grant it already produced (RFC 6749 §4.1.2).
- Deleted and disabled users cannot access or renew. Grants bind the user node identifier and protected creation time, so a recreated username cannot inherit old credentials. AEM permission changes apply to the next request.
- Raw access, refresh and consent credentials are not stored; records contain SHA-256 hashes.

### How a grant ends

- **Disconnect from Gradial** calls `/revoke`.
- **Absolute expiry** after `grantSeconds`.
- **Disabling the service** (`enabled: false` or removing its configuration) blocks every request at once. Changing the client ID or secret does the same.
- **Disabling or deleting the AEM user.**
- **Becoming an administrator** (unless `allowAdministrators`).
- **Eviction** when the user opens an eleventh grant.
- **Deleting the nodes** under `/var/gradial/obo/grants` as an administrator.

**A password change does not revoke grants.** To cut off a user whose credentials may be compromised, disable the account, revoke from Gradial, or delete their grants.

### Cleanup

A scheduled job (every 10 minutes, `scheduler.runOn=LEADER`, not concurrent) removes expired and revoked grants and consents and empty user folders. It saves every 200 removals, so no commit grows with the store, and stops after 60 seconds; the next run resumes there. A grant is one node with no children, so removing one is one node.

### Clustered Author

On MongoMK, a grant written on one cluster node becomes visible on the others after the background read (about one second by default). A token issued or refreshed on one node and used on another within that window gets 403. Route each client to one Author node (sticky sessions, which Adobe recommends for clustered Authors), or retry once after a short delay. Two concurrent refreshes of the same credential on different nodes conflict when the second commits; that refresh fails and revokes the family, as on a single node.

## Audit log

Security events go to logger `com.gradial.core.oauth.obo.audit` at INFO, written to `logs/gradial-obo-audit.log` on Author by the shipped log configuration. Lines never contain a credential; grants are identified by a short fingerprint that cannot be turned back into a credential:

```
gradial-obo event=consent_approved user=jdoe grant=3f9a0c1b2d4e
gradial-obo event=grant_issued user=jdoe grant=3f9a0c1b2d4e
gradial-obo event=grant_revoked user=jdoe grant=3f9a0c1b2d4e reason=refresh_replay
```

Events: `service_enabled`, `consent_approved`, `consent_denied`, `consent_refused` (`reason=impersonation|delegated_session`), `delegation_refused` (`reason=administrator`), `grant_issued`, `grant_revoked` (`reason=disconnect|refresh_replay|refresh_race|code_replay`), `grant_evicted`, `path_refused`. Each refresh logs `grant_refreshed` at DEBUG. Cleanup failures log a WARN with the exception.

## Compatibility and validation

Compilation does not establish runtime compatibility. For each supported deployment, prove ordinary-user identity; allowed and denied reads and writes; real creator and modifier properties; permission changes; disabled and deleted users; renewal after expiry; single-use codes and refresh; effective revocation; concurrent refresh behavior; denied paths. Inspect denied paths as an administrator to confirm no content was created.

Unit tests run the login module, repoinit script and ACLs against real Oak: the AEM 6.5 SP25 stack on Java 8 and 11 builds, the 6.5 LTS stack on Java 17 and later. Other tests cover consent binding, impersonated and delegated-session consent, administrator refusal, the exact consent origin, caps and cleanup, exact callbacks and PKCE, code replay, credential-type confusion, rotation and replay revocation, a conflicting concurrent refresh, expiry, configuration changes, disabled, deleted and recreated users, client authentication, denied paths, the audit log, and existing-handler compatibility. True multi-session and cluster concurrency need live probes. Live results belong in PR evidence.
