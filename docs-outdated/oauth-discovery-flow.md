# OAuth 2.1 Discovery Flow

This document describes the OAuth 2.1 Authorization Server Metadata discovery implementation (RFC 8414) in Authly, enabling automatic client configuration and server capability detection.

## Overview

OAuth Discovery provides a standardized way for clients to automatically discover an authorization server's capabilities, endpoints, and supported features. This eliminates manual configuration and enables dynamic client adaptation to server capabilities.

## Visual Discovery Flow

![OAuth Discovery Flow](oauth-discovery-flow.mmd)

## Discovery Process

### 1. Discovery URL Construction

Clients construct the discovery URL using the well-known path:

```
https://{authorization_server}/.well-known/oauth-authorization-server
```

**Examples:**
- `https://auth.example.com/.well-known/oauth-authorization-server`
- `https://api.example.com/oauth/.well-known/oauth-authorization-server`
- `https://example.com/auth/.well-known/oauth-authorization-server`

### 2. Metadata Request

**HTTP Request:**
```http
GET /.well-known/oauth-authorization-server HTTP/1.1
Host: auth.example.com
Accept: application/json
User-Agent: MyApp/1.0.0
```

**Security Headers:**
- **HTTPS Required**: Discovery must occur over secure connections
- **CORS Support**: Allows browser-based clients to access metadata
- **Rate Limiting**: Prevents abuse of discovery endpoint

### 3. Server Processing

The authorization server processes the discovery request through several steps:

#### Configuration Assembly
- **Issuer Identification**: Server's canonical identifier
- **Base URL Detection**: Determines server base URL from request or configuration
- **Endpoint Construction**: Builds complete endpoint URLs

#### Dynamic Capability Assessment
- **Scope Discovery**: Queries database for active scopes
- **Feature Detection**: Determines supported OAuth features
- **Algorithm Support**: Lists supported cryptographic methods

#### URL Building
- **Reverse Proxy Support**: Handles X-Forwarded-* headers
- **Protocol Detection**: HTTP vs HTTPS endpoint construction
- **Path Normalization**: Consistent URL formatting

### 4. Metadata Response

**HTTP Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: public, max-age=3600
Access-Control-Allow-Origin: *

{
  "issuer": "https://auth.example.com",
  "authorization_endpoint": "https://auth.example.com/authorize",
  "token_endpoint": "https://auth.example.com/auth/token",
  "revocation_endpoint": "https://auth.example.com/auth/revoke",
  "scopes_supported": ["read", "write", "admin", "profile"],
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "password", "refresh_token"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": [
    "client_secret_basic",
    "client_secret_post"
  ]
}
```

## Metadata Fields

### Required Fields (RFC 8414)

#### issuer
- **Type**: String (URL)
- **Description**: Authorization server's identifier
- **Example**: `"https://auth.example.com"`
- **Validation**: Must match the server's actual identity

#### authorization_endpoint
- **Type**: String (URL)
- **Description**: OAuth 2.1 authorization endpoint
- **Example**: `"https://auth.example.com/authorize"`
- **Usage**: Client redirects users here for authorization

#### token_endpoint
- **Type**: String (URL)
- **Description**: Token exchange endpoint
- **Example**: `"https://auth.example.com/auth/token"`
- **Usage**: Exchange authorization codes and refresh tokens

### Optional Fields (Enhanced)

#### revocation_endpoint
- **Type**: String (URL)
- **Description**: RFC 7009 token revocation endpoint
- **Example**: `"https://auth.example.com/auth/revoke"`
- **Usage**: Revoke access and refresh tokens

#### scopes_supported
- **Type**: Array of Strings
- **Description**: Available permission scopes
- **Example**: `["read", "write", "admin", "profile"]`
- **Dynamic**: Retrieved from active scopes in database

#### response_types_supported
- **Type**: Array of Strings
- **Description**: Supported OAuth response types
- **Example**: `["code"]`
- **OAuth 2.1**: Only authorization code flow supported

#### grant_types_supported
- **Type**: Array of Strings
- **Description**: Supported grant types
- **Example**: `["authorization_code", "password", "refresh_token"]`
- **Multi-grant**: Both OAuth and password authentication

#### code_challenge_methods_supported
- **Type**: Array of Strings
- **Description**: PKCE methods supported
- **Example**: `["S256"]`
- **OAuth 2.1**: Mandatory PKCE with S256

#### token_endpoint_auth_methods_supported
- **Type**: Array of Strings
- **Description**: Client authentication methods
- **Example**: `["client_secret_basic", "client_secret_post"]`
- **Security**: Multiple authentication options for confidential clients

## Client Auto-Configuration

### Web Application Configuration

Using discovery metadata, web applications can auto-configure:

```javascript
// Fetch discovery metadata
const response = await fetch('https://auth.example.com/.well-known/oauth-authorization-server');
const metadata = await response.json();

// Configure OAuth client
const oauthConfig = {
  authorizationEndpoint: metadata.authorization_endpoint,
  tokenEndpoint: metadata.token_endpoint,
  revocationEndpoint: metadata.revocation_endpoint,
  scopes: metadata.scopes_supported,
  pkceRequired: metadata.code_challenge_methods_supported.includes('S256'),
  clientAuthMethods: metadata.token_endpoint_auth_methods_supported
};

// Generate authorization URL
const authUrl = `${oauthConfig.authorizationEndpoint}?` +
  `response_type=code&` +
  `client_id=${clientId}&` +
  `redirect_uri=${encodeURIComponent(redirectUri)}&` +
  `scope=${encodeURIComponent(oauthConfig.scopes.join(' '))}&` +
  `state=${state}&` +
  `code_challenge=${codeChallenge}&` +
  `code_challenge_method=S256`;
```

### Mobile Application Configuration

Mobile apps benefit from automatic PKCE configuration:

```swift
// Swift iOS example
struct OAuthConfig {
    let authorizationEndpoint: URL
    let tokenEndpoint: URL
    let revocationEndpoint: URL
    let supportedScopes: [String]
    let pkceRequired: Bool
}

func configureFromDiscovery(serverURL: URL) async throws -> OAuthConfig {
    let discoveryURL = serverURL.appendingPathComponent("/.well-known/oauth-authorization-server")
    let (data, _) = try await URLSession.shared.data(from: discoveryURL)
    let metadata = try JSONDecoder().decode(OAuthMetadata.self, from: data)
    
    return OAuthConfig(
        authorizationEndpoint: URL(string: metadata.authorization_endpoint)!,
        tokenEndpoint: URL(string: metadata.token_endpoint)!,
        revocationEndpoint: URL(string: metadata.revocation_endpoint)!,
        supportedScopes: metadata.scopes_supported,
        pkceRequired: metadata.code_challenge_methods_supported.contains("S256")
    )
}
```

### Server-to-Server Configuration

Backend services can discover token endpoints:

```python
import httpx
import json

async def configure_oauth_client(server_url: str):
    discovery_url = f"{server_url}/.well-known/oauth-authorization-server"
    
    async with httpx.AsyncClient() as client:
        response = await client.get(discovery_url)
        response.raise_for_status()
        metadata = response.json()
    
    return {
        'token_endpoint': metadata['token_endpoint'],
        'revocation_endpoint': metadata.get('revocation_endpoint'),
        'auth_methods': metadata.get('token_endpoint_auth_methods_supported', []),
        'supported_scopes': metadata.get('scopes_supported', [])
    }

# Usage
config = await configure_oauth_client("https://auth.example.com")
token_response = await httpx.post(config['token_endpoint'], data={
    'grant_type': 'client_credentials',
    'client_id': client_id,
    'client_secret': client_secret,
    'scope': ' '.join(config['supported_scopes'])
})
```

## Implementation Details

### Dynamic Scope Discovery

The server dynamically discovers available scopes:

```sql
-- Query for active scopes
SELECT scope_name 
FROM scopes 
WHERE is_active = true 
ORDER BY scope_name;
```

This ensures the metadata always reflects current server capabilities without manual updates.

### URL Construction Logic

```python
def build_endpoint_urls(request: Request, base_path: str = "") -> dict:
    """Build endpoint URLs with reverse proxy support."""
    
    # Detect base URL from request
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host", request.url.hostname)
    port = request.headers.get("x-forwarded-port")
    
    # Construct base URL
    base_url = f"{scheme}://{host}"
    if port and port not in ["80", "443"]:
        base_url += f":{port}"
    
    if base_path:
        base_url += base_path
    
    return {
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/authorize",
        "token_endpoint": f"{base_url}/auth/token",
        "revocation_endpoint": f"{base_url}/auth/revoke"
    }
```

### Caching Strategy

**Server-Side Caching:**
- Metadata cached for 1 hour to reduce database queries
- Scope list cached until scope changes detected
- Configuration cached in memory for performance

**Client-Side Caching:**
- Respect HTTP cache headers (Cache-Control, ETag)
- Cache discovery data for application session
- Periodic refresh for long-running applications

## Error Handling

### Server Errors

**Database Connectivity Issues:**
```python
try:
    scopes = await scope_repository.get_active_scopes()
except DatabaseError:
    # Graceful degradation - return core metadata without scopes
    scopes = []
    logger.warning("Database unavailable during discovery - returning minimal metadata")
```

**Configuration Errors:**
- Missing base URL configuration
- Invalid endpoint path configuration
- Certificate/TLS issues

### Client Errors

**Network Issues:**
```javascript
async function discoverOAuthConfig(serverUrl) {
    try {
        const response = await fetch(`${serverUrl}/.well-known/oauth-authorization-server`, {
            timeout: 10000,
            headers: { 'Accept': 'application/json' }
        });
        
        if (!response.ok) {
            throw new Error(`Discovery failed: ${response.status}`);
        }
        
        return await response.json();
    } catch (error) {
        console.warn('OAuth discovery failed, using fallback configuration', error);
        return getFallbackConfig();
    }
}
```

**Validation Errors:**
- Missing required metadata fields
- Invalid URL formats in metadata
- Unsupported server capabilities

## Security Considerations

### Transport Security
- **HTTPS Required**: Discovery endpoint must use secure transport
- **Certificate Validation**: Clients must validate server certificates
- **Secure Redirects**: Discovered endpoints must use HTTPS

### Metadata Validation
- **Issuer Verification**: Client must validate issuer matches expected server
- **URL Validation**: All discovered URLs must be properly formatted and secure
- **Capability Matching**: Client requirements must match server capabilities

### Privacy Protection
- **No Sensitive Data**: Metadata contains no user or client-specific information
- **Public Information**: All metadata is safe for public disclosure
- **Rate Limiting**: Prevent abuse of discovery endpoint

## Standards Compliance

### RFC 8414 Compliance
- **Required Fields**: All mandatory metadata fields included
- **Optional Extensions**: Additional fields for enhanced functionality
- **Content Type**: Proper application/json content type
- **HTTP Caching**: Appropriate cache headers for performance

### OAuth 2.1 Alignment
- **PKCE Indication**: Advertises mandatory PKCE support
- **Grant Type Accuracy**: Lists only supported grant types
- **Security Features**: Highlights security-enhanced capabilities

## Monitoring and Analytics

### Discovery Metrics
```python
# Example metrics collection
discovery_requests_total = Counter('oauth_discovery_requests_total', 'Total discovery requests')
discovery_request_duration = Histogram('oauth_discovery_request_duration_seconds', 'Discovery request duration')
discovery_errors_total = Counter('oauth_discovery_errors_total', 'Discovery request errors', ['error_type'])

@discovery_metrics
async def handle_discovery_request():
    with discovery_request_duration.time():
        discovery_requests_total.inc()
        try:
            return await generate_metadata()
        except Exception as e:
            discovery_errors_total.labels(error_type=type(e).__name__).inc()
            raise
```

### Health Monitoring
- **Endpoint Availability**: Monitor discovery endpoint uptime
- **Response Time**: Track metadata generation performance
- **Error Rates**: Monitor and alert on discovery failures
- **Cache Hit Rates**: Optimize caching strategy based on usage

This comprehensive discovery implementation enables seamless OAuth 2.1 client integration while maintaining security, performance, and standards compliance.