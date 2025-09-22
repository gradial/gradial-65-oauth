import axios, { AxiosInstance, AxiosError } from 'axios';
import https from 'https';
import jwt from 'jsonwebtoken';
import forge from 'node-forge';
import fs from 'fs';

interface OAuthTokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  scope?: string;
}

interface OAuthConfig {
  clientId: string;
  clientSecret: string;
  scope: string;
  aemHost: string;
  tokenEndpoint: string;
  redirectUri: string;
  authorizationCode?: string;
  p12Path?: string;
  p12Password?: string;
  issuer?: string;
}

class AEMOAuthAuthenticator {
  private config: OAuthConfig;
  private axiosInstance: AxiosInstance;

  constructor(config: Partial<OAuthConfig> = {}) {
    this.config = {
      clientId: '', //update this to the clientId from your AEM OAuth Client
      clientSecret: '', //update this to the clientSecret from your AEM OAuth Client
      scope: 'read_all', // DO NOT MODIFY THIS
      aemHost: '', //Update this with your instance host - example: https://localhost:4502
      tokenEndpoint: '/oauth/token', // DO NOT MODIFY THIS
      redirectUri: 'https://www.gradial.com/api/v1/auth/aem65/oauth2/callback', // DO NOT MODIFY THIS
      authorizationCode: config.authorizationCode, // DO NOT MODIFY THIS
      p12Path: '/path/to/your/aem-cert.p12', //update this path to the location of your p12 file downloaded from the AEM OAuth Client page
      p12Password: 'notasecret', // The password for your p12 file.  Update if different
      issuer: '' //update this to the clientId
    };

    this.axiosInstance = axios.create({
      baseURL: this.config.aemHost,
      httpsAgent: new https.Agent({
        rejectUnauthorized: false
      }),
      timeout: 30000,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });
  }

  getAuthorizationUrl(): string {
    const authUrl = `${this.config.aemHost}/oauth/authorize`;
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      scope: this.config.scope
    });
    return `${authUrl}?${params.toString()}`;
  }

  private extractPrivateKeyFromP12(): string {
    try {
      const p12Der = fs.readFileSync(this.config.p12Path!);
      const p12Asn1 = forge.asn1.fromDer(p12Der.toString('binary'));
      const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, this.config.p12Password!);
      
      const bags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
      const keyBag = bags[forge.pki.oids.pkcs8ShroudedKeyBag]![0];
      
      if (!keyBag || !keyBag.key) {
        throw new Error('No private key found in P12 file');
      }
      
      return forge.pki.privateKeyToPem(keyBag.key);
    } catch (error) {
      console.error('Error extracting private key from P12:', error);
      throw error;
    }
  }

  private createJWT(): string {
    const privateKey = this.extractPrivateKeyFromP12();
    
    const now = Math.floor(Date.now() / 1000);
    const expiry = now + 3600; // 1 hour
    
    const payload = {
      iss: this.config.issuer,
      sub: this.config.clientId,
      aud: `${this.config.aemHost}/oauth/token`,
      exp: expiry,
      iat: now,
      scope: this.config.scope
    };
    
    return jwt.sign(payload, privateKey, { algorithm: 'RS256' });
  }

  async getAccessTokenWithJWT(): Promise<OAuthTokenResponse> {
    const tokenUrl = `${this.config.tokenEndpoint}`;
    
    try {
      const jwtToken = this.createJWT();
      
      const params = new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        assertion: jwtToken,
        client_id: this.config.clientId
      });

      console.log(`🔐 Requesting OAuth token with JWT Bearer from: ${this.config.aemHost}${tokenUrl}`);
      console.log(`📋 Scope requested: ${this.config.scope}`);
      console.log(`🔑 Using P12 certificate: ${this.config.p12Path}`);
      
      const response = await this.axiosInstance.post<OAuthTokenResponse>(
        tokenUrl,
        params.toString()
      );

      console.log(`✅ Token obtained successfully with JWT Bearer`);
      console.log(`   Token type: ${response.data.token_type}`);
      console.log(`   Expires in: ${response.data.expires_in} seconds`);
      console.log(`   Scope granted: ${response.data.scope || 'not specified'}`);
      
      return response.data;
    } catch (error) {
      const axiosError = error as AxiosError;
      console.error(`❌ Failed to obtain access token with JWT Bearer`);
      
      if (axiosError.response) {
        console.error(`   Status: ${axiosError.response.status}`);
        console.error(`   Message: ${JSON.stringify(axiosError.response.data)}`);
      } else if (axiosError.request) {
        console.error(`   No response received from server`);
        console.error(`   Check if AEM is running at: ${this.config.aemHost}`);
      } else {
        console.error(`   Error: ${axiosError.message}`);
      }
      
      throw error;
    }
  }


  async getAccessToken(): Promise<OAuthTokenResponse> {
    const tokenUrl = `${this.config.tokenEndpoint}`;
    
    const params = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
      scope: this.config.scope,
      redirect_uri: this.config.redirectUri,
      code: this.config.authorizationCode || ''
    });

    try {
      console.log(`🔐 Requesting OAuth token from: ${this.config.aemHost}${tokenUrl}`);
      console.log(`📋 Scope requested: ${this.config.scope}`);
      
      const response = await this.axiosInstance.post<OAuthTokenResponse>(
        tokenUrl,
        params.toString()
      );

      console.log(`✅ Token obtained successfully`);
      console.log(`   Token type: ${response.data.token_type}`);
      console.log(`   Expires in: ${response.data.expires_in} seconds`);
      console.log(`   Scope granted: ${response.data.scope || 'not specified'}`);
      
      return response.data;
    } catch (error) {
      const axiosError = error as AxiosError;
      console.error(`❌ Failed to obtain access token`);
      
      if (axiosError.response) {
        console.error(`   Status: ${axiosError.response.status}`);
        console.error(`   Message: ${JSON.stringify(axiosError.response.data)}`);
      } else if (axiosError.request) {
        console.error(`   No response received from server`);
        console.error(`   Check if AEM is running at: ${this.config.aemHost}`);
      } else {
        console.error(`   Error: ${axiosError.message}`);
      }
      
      throw error;
    }
  }

  async testAuthenticatedRequest(token: string, resourcePath: string = '/content/dam.json'): Promise<any> {
    try {
      console.log(`\n🔍 Testing authenticated request to: ${resourcePath}`);
      
      const response = await this.axiosInstance.get(resourcePath, {
        headers: {
          'Authorization': `Bearer ${token}`
        },
        params: {
          limit: 5
        }
      });

      console.log(`✅ Authenticated request successful`);
      console.log(`   Status: ${response.status}`);
      console.log(`   Content-Type: ${response.headers['content-type']}`);
      
      return response.data;
    } catch (error) {
      const axiosError = error as AxiosError;
      console.error(`❌ Authenticated request failed`);
      
      if (axiosError.response) {
        console.error(`   Status: ${axiosError.response.status}`);
        if (axiosError.response.status === 403) {
          console.error(`   The scope '${this.config.scope}' may not have access to ${resourcePath}`);
        }
      }
      
      throw error;
    }
  }

}

async function runTests() {
  console.log('========================================');
  console.log('AEM OAuth Authentication Test');
  console.log('========================================\n');

  const authenticator = new AEMOAuthAuthenticator();
  
  try {
    console.log('Test 1: OAuth Token Request');
    console.log('--------------------------------');
    
    let tokenResponse: OAuthTokenResponse;
    
    // Try JWT Bearer flow first (server-to-server)
    try {
      console.log('Attempting JWT Bearer flow (server-to-server)...');
      tokenResponse = await authenticator.getAccessTokenWithJWT();
      console.log(`\n💚 Test 1 PASSED: Successfully obtained access token with JWT Bearer\n`);
    } catch (jwtError) {
      console.log(`\n⚠️  JWT Bearer flow failed, trying authorization code flow...`);
      console.log(`\nTo use authorization code flow:`);
      console.log(`1. Visit this URL in your browser:`);
      console.log(`   ${authenticator.getAuthorizationUrl()}`);
      console.log(`2. Login and authorize the application`);
      console.log(`3. Copy the 'code' parameter from the redirect URL`);
      console.log(`4. Pass it as authorizationCode in the config\n`);
      
      console.log(`Using authorization code flow with placeholder code...`);
      tokenResponse = await authenticator.getAccessToken();
      console.log(`\n💚 Test 1 PASSED: Successfully obtained access token with authorization_code\n`);
    }

    console.log('\nTest 2: Authenticated Request');
    console.log('--------------------------------');
    await authenticator.testAuthenticatedRequest(tokenResponse.access_token);
    console.log(`💚 Test 2 PASSED: Authenticated request successful\n`);

    console.log('\nTest 3: Test Different Resource Paths');
    console.log('--------------------------------');
    const testPaths = [
      '/content.json',
      '/content/dam.json',
      '/content/gradial-65.json'
    ];

    for (const path of testPaths) {
      try {
        await authenticator.testAuthenticatedRequest(tokenResponse.access_token, path);
        console.log(`   ✅ Access granted to: ${path}`);
      } catch (error) {
        const axiosError = error as AxiosError;
        if (axiosError.response?.status === 403) {
          console.log(`   ⛔ Access denied to: ${path}`);
        } else if (axiosError.response?.status === 404) {
          console.log(`   ⚠️  Path not found: ${path}`);
        } else {
          console.log(`   ❌ Error accessing: ${path}`);
        }
      }
    }

    console.log('\n========================================');
    console.log('✅ All critical tests completed successfully!');
    console.log('========================================');
    
  } catch (error) {
    console.error('\n========================================');
    console.error('❌ Test suite failed');
    console.error('========================================');
    process.exit(1);
  }
}

if (require.main === module) {
  runTests().catch(console.error);
}

export { AEMOAuthAuthenticator, OAuthTokenResponse, OAuthConfig };