# AEM 6.5 Dynamic OAuth Scopes Implementation

This project implements a dynamic OAuth scope system for Adobe Experience Manager (AEM) 6.5, allowing for flexible configuration of OAuth scopes through OSGi configurations rather than requiring Java code deployment for each new scope.

## Features

- **Dynamic OAuth Scope Configuration**: Define OAuth scopes through OSGi configurations
- **Flexible Permission Management**: Configure JCR privileges per scope
- **Resource Path Control**: Define specific content paths accessible by each scope
- **OAuth Test Suite**: TypeScript-based testing tool for validating OAuth authentication

## Project Structure

```
gradial/
├── core/                    # Java bundle with OAuth implementation
│   └── src/main/java/com/gradial/core/oauth/
│       ├── config/         # OSGi configuration interfaces
│       └── scopes/         # Dynamic scope implementation
├── ui.config/              # OSGi configurations
│   └── src/main/content/jcr_root/apps/gradial/osgiconfig/
│       └── config.author/  # OAuth scope configurations
├── ui.apps/                # AEM application components
├── ui.content/             # Sample content
└── all/                    # Combined deployment package
```

## OAuth Scopes

The following OAuth scopes are pre-configured:

| Scope | Description | Resource Path | Privileges |
|-------|-------------|---------------|------------|
| `read_all` | Read-only access to entire repository | `/` | `jcr:read` |
| `site_author` | Author site content | `/content` | Read, Write, Lock, Version |
| `upload_assets` | Upload assets to DAM | `/content/dam` | Read, Write, Lock, Version |
| `publish_assets` | Publish DAM assets | `/content/dam` | Read, Add Nodes, Replicate |
| `launch_author` | Author launches | `/content/launches` | Read, Write, Lock, Version |
| `tags_author` | Manage tags | `/content/cq:tags` | Read, Write, Version, Replicate |
| `site_xf_author` | Author experience fragments | `/content/experience-fragments` | Read, Write, Lock, Version |

## Installation

### Prerequisites

- AEM 6.5 instance running locally
- Java 11
- Maven 3.6+
- Node.js 16+ (for OAuth testing)

### Build and Deploy

1. Build and deploy all modules:
```bash
mvn clean install -PautoInstallSinglePackage
```

2. Or deploy specific modules:
```bash
# Deploy only the core bundle
cd core
mvn clean install -PautoInstallBundle

# Deploy only configurations
cd ui.config
mvn clean install -PautoInstallPackage
```

## OAuth Configuration

### Creating a New OAuth Scope

1. Create a new OSGi configuration file in `ui.config/src/main/content/jcr_root/apps/gradial/osgiconfig/config.author/`:

```json
{
    "scopeName": "your_scope_name",
    "resourcePath": "/content/your-path",
    "requiredPrivileges": ["jcr:read", "rep:write"]
}
```

2. Name the file following the pattern: `com.gradial.core.oauth.scopes.DynamicScope~[scope-identifier].cfg.json`

3. Deploy the configuration:
```bash
cd ui.config
mvn clean install -PautoInstallPackage
```

### Every resourcePath must exist

Each scope's `resourcePath` must exist on every environment where the configuration is deployed. Granite OAuth 1.1.34 handles a missing path badly, and this package does not change that:

- **Authorization-code flow:** consent fails. `OAuth2AuthorizationCodeIssuer.doPost` throws `OAuthSystemException: failed while accessing repository` and the consent POST returns 500, also when valid scopes are requested in the same request.
- **JWT bearer grant (what Gradial uses):** the token is issued, but it gets no access anywhere. Every content read returns 404, including reads under the other scopes in the same token.

This package therefore **detects and logs** a missing path; it never refuses the scope. A scope always registers when its name is free, and AEM logs one ERROR naming the scope and the path:

- at activation;
- when the path, or an ancestor, is added or removed (a Sling resource change listener; no polling, no restart). The ERROR repeats only after the path came back, which logs one INFO;
- when the reader user becomes available after the scopes activated (a fresh install), without a restart;
- when Granite reads the scope's path to issue a token, at most once every 15 minutes per scope.

Gradial's own health check shows the user-facing message.

The check runs as the service user `gradial-oauth-scope-reader`, created on Author by this package's repository initializer, with only `rep:readNodes` on `/`: it can see that nodes exist but cannot read properties. Oak evaluates permission entries for user principals before those for group principals, so this user's own allow on `/` wins over a `deny jcr:read` for `everyone` on a scope's path: such a deny does not cause a false report. An existing path is hidden from the reader only by a deny entry for `gradial-oauth-scope-reader` itself, or by a closed user group on the path or an ancestor where CUG evaluation is enabled (it is off on Author by default).

The initializer creates the user and its ACL with the JCR and Jackrabbit APIs, with the same result as these repoinit statements (`create service user gradial-oauth-scope-reader with path system/gradial`, then `set ACL for gradial-oauth-scope-reader` / `allow rep:readNodes on /` / `end`). It does not use Sling's repoinit services because AEM 6.5's API controller refuses to wire customer bundles to `org.apache.sling.repoinit.parser`. It also never uses a repoinit configuration: if a normal user or a group named `gradial-oauth-scope-reader` already exists, it leaves that account untouched, sets nothing up and logs one ERROR, and it never fails, so AEM always starts. Scopes then register with one WARN each that their paths are unchecked, which is also what happens on a deployment that copies the scope class without this package's configurations.

### Scope names must be unique

Granite keeps one scope per name. A scope registered later with the same name silently replaces the earlier one, and unregistering either removes the name for both. Another bundle can define scopes too (for example an older copy of this package's scope classes, or a customer's own scopes). So a DynamicScope configuration whose `scopeName` is already registered by another scope, in this bundle or any other, is not registered, and AEM logs one ERROR naming both definitions. Remove or rename one of them. Scope names are part of each Gradial connection's configuration, so renaming one means updating the connections that request it.

### Available JCR Privileges

- `jcr:read` - Read access
- `rep:write` - Write access
- `jcr:addChildNodes` - Add child nodes
- `jcr:removeNode` - Remove nodes
- `jcr:removeChildNodes` - Remove child nodes
- `jcr:modifyProperties` - Modify properties
- `jcr:lockManagement` - Lock/unlock nodes
- `jcr:versionManagement` - Version management
- `crx:replicate` - Replication/publish rights

## OAuth Testing

### Setup OAuth Test Tool

1. Install dependencies:
```bash
npm install
```

2. Configure OAuth credentials in `aem-oauth-test.ts`:
```typescript
clientId: 'your-client-id',
clientSecret: 'your-client-secret',
scope: 'desired_scope'
```

### Run OAuth Tests

```bash
npm test
```

The test suite will:
1. Attempt JWT Bearer authentication (server-to-server)
2. Fall back to authorization code flow if needed
3. Test authenticated API requests
4. Validate access to various resource paths

### JWT Bearer Authentication

For server-to-server authentication, place your P12 certificate in the project root and update the test configuration:
```typescript
p12Path: '/path/to/your/certificate.p12',
p12Password: 'your-password'
```

## Development

### Project Configuration

- **Maven Profiles**:
  - `autoInstallSinglePackage` - Deploy full package to AEM
  - `autoInstallBundle` - Deploy only Java bundle
  - `autoInstallPackage` - Deploy only content package

### Local Development

1. Start AEM instance:
```bash
java -jar aem-author-p4502.jar
```

2. Build and deploy:
```bash
mvn clean install -PautoInstallSinglePackage
```

3. Access OSGi console: http://localhost:4502/system/console/components

4. Verify OAuth scopes are registered: Search for `com.gradial.core.oauth.scopes.DynamicScope`

## Troubleshooting

### Component Not Starting

If the DynamicScope component shows as "no config" in OSGi:
1. Verify configuration PID matches: `com.gradial.core.oauth.scopes.DynamicScope`
2. Check configuration file naming pattern
3. Ensure configuration is deployed to correct runmode folder

### OAuth Token Request Failures

- **400 Bad Request**: Check grant_type and required parameters
- **401 Unauthorized**: Verify client credentials
- **403 Forbidden**: Scope may not have access to requested resource
- **400 `invalid_scope`**: A requested scope is not registered. Check `error.log` for `OAuth scope <name> not registered`: another scope already uses the name.
- **Consent fails with 500, or the token is issued but every read returns 404**: one requested scope's `resourcePath` is missing. Check `error.log` for `OAuth scope <name> is registered, but its resource path ... is missing or not visible`.

## License

Apache License 2.0

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## Support

For issues and questions, please create an issue in the GitHub repository.
