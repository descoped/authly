# JWKS endpoint fix

On first request a jwks is created, then if fails to be obtained.

```
authly-app       | INFO:     127.0.0.1:36584 - "GET /health HTTP/1.1" 200 OK
authly-app       | INFO:     127.0.0.1:35240 - "GET /health HTTP/1.1" 200 OK
authly-app       | INFO:     127.0.0.1:57316 - "GET /health HTTP/1.1" 200 OK
authly-app       | INFO:     127.0.0.1:38506 - "GET /health HTTP/1.1" 200 OK
authly-app       | INFO:     127.0.0.1:39612 - "GET /health HTTP/1.1" 200 OK
authly-app       | 2025-07-30 08:56:28,340 - authly.oidc.jwks - INFO - No key pairs found, generating initial key pair
authly-app       | 2025-07-30 08:56:28,340 - authly.oidc.jwks - INFO - Generating RSA key pair synchronously (size: 2048, algorithm: RS256)
authly-app       | 2025-07-30 08:56:28,361 - authly.oidc.jwks - INFO - Generated RSA key pair synchronously with ID: key_20250730085628361026
authly-app       | 2025-07-30 08:56:28,361 - authly.oidc.jwks - INFO - Generated JWKS with 1 keys
authly-app       | 2025-07-30 08:56:28,361 - authly.api.oidc_router - INFO - JWKS endpoint accessed successfully
authly-app       | INFO:     151.101.2.132:47166 - "GET /.well-known/jwks.json HTTP/1.1" 200 OK
authly-app       | INFO:     127.0.0.1:36828 - "GET /health HTTP/1.1" 200 OK




authly-app       | 2025-07-30 08:56:53,268 - authly.oauth.scope_repository - ERROR - Error in get_active_scopes: 'Depends' object has no attribute 'cursor'
authly-app       | 2025-07-30 08:56:53,268 - authly.oauth.discovery_service - WARNING - Failed to retrieve scopes for discovery: Failed to get active scopes: 'Depends' object has no attribute 'cursor'
authly-app       | 2025-07-30 08:56:53,268 - authly.oauth.discovery_service - INFO - Generated OAuth 2.1 server metadata for issuer: http://localhost:8000
authly-app       | 2025-07-30 08:56:53,269 - authly.api.oidc_router - ERROR - Error generating OIDC discovery metadata: unsupported operand type(s) for +: 'NoneType' and 'list'
authly-app       | 2025-07-30 08:56:53,269 - authly.api.oidc_router - WARNING - Returned static OIDC discovery metadata due to error
authly-app       | INFO:     151.101.2.132:45140 - "GET /.well-known/openid_configuration HTTP/1.1" 200 OK
authly-app       | INFO:     127.0.0.1:59750 - "GET /health HTTP/1.1" 200 OK 
```
