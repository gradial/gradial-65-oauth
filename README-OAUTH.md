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
