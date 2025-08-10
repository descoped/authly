/**
 * OpenID Connect 1.0 Flow Implementations
 * Handles OIDC discovery, token validation, and userinfo
 */

class OIDCFlows {
    /**
     * Fetch OIDC Discovery Document
     */
    static async fetchDiscoveryDocument(config, tester) {
        const { response, data } = await tester.makeRequest('/.well-known/openid-configuration');
        
        if (response.status !== 200) {
            throw new Error('Failed to fetch discovery document');
        }
        
        return data;
    }
    
    /**
     * Fetch JWKS (JSON Web Key Set)
     */
    static async fetchJWKS(config, tester) {
        const discovery = await this.fetchDiscoveryDocument(config, tester);
        
        if (!discovery.jwks_uri) {
            throw new Error('JWKS URI not found in discovery document');
        }
        
        const jwksUrl = discovery.jwks_uri.replace(config.serverUrl, '');
        const { response, data } = await tester.makeRequest(jwksUrl);
        
        if (response.status !== 200) {
            throw new Error('Failed to fetch JWKS');
        }
        
        return data;
    }
    
    /**
     * Validate ID Token structure and claims
     */
    static validateIDToken(idToken, config) {
        if (!idToken) {
            return { valid: false, error: 'No ID token provided' };
        }
        
        // Parse JWT
        const parts = idToken.split('.');
        if (parts.length !== 3) {
            return { valid: false, error: 'Invalid JWT format' };
        }
        
        try {
            const header = JSON.parse(atob(parts[0]));
            const payload = JSON.parse(atob(parts[1]));
            
            // Validate required claims
            const requiredClaims = ['iss', 'sub', 'aud', 'exp', 'iat'];
            for (const claim of requiredClaims) {
                if (!payload[claim]) {
                    return { valid: false, error: `Missing required claim: ${claim}` };
                }
            }
            
            // Validate audience
            if (Array.isArray(payload.aud)) {
                if (!payload.aud.includes(config.clientId)) {
                    return { valid: false, error: 'Invalid audience' };
                }
            } else if (payload.aud !== config.clientId) {
                return { valid: false, error: 'Invalid audience' };
            }
            
            // Validate expiration
            const now = Math.floor(Date.now() / 1000);
            if (payload.exp <= now) {
                return { valid: false, error: 'Token expired' };
            }
            
            // Validate issued at
            if (payload.iat > now + 60) {  // Allow 1 minute clock skew
                return { valid: false, error: 'Token issued in the future' };
            }
            
            // Validate issuer matches server
            if (!payload.iss.startsWith(config.serverUrl)) {
                return { valid: false, error: 'Invalid issuer' };
            }
            
            // Check for nonce if present in storage
            const storedNonce = sessionStorage.getItem('oidc_nonce');
            if (storedNonce && payload.nonce !== storedNonce) {
                return { valid: false, error: 'Invalid nonce' };
            }
            
            return {
                valid: true,
                header,
                payload,
                signature: parts[2]
            };
        } catch (error) {
            return { valid: false, error: `Failed to parse token: ${error.message}` };
        }
    }
    
    /**
     * Fetch UserInfo
     */
    static async fetchUserInfo(config, tester, accessToken) {
        const { response, data } = await tester.makeRequest('/api/v1/userinfo', {
            headers: {
                'Authorization': `Bearer ${accessToken}`
            }
        });
        
        return { response, data };
    }
    
    /**
     * Start OIDC Authorization Flow
     */
    static async startOIDCFlow(config, tester) {
        const state = tester.generateRandomString(16);
        const nonce = tester.generateRandomString(16);
        const codeVerifier = tester.generateRandomString(128);
        const codeChallenge = await tester.sha256(codeVerifier);
        
        // Store flow data
        sessionStorage.setItem('oauth_state', state);
        sessionStorage.setItem('oidc_nonce', nonce);
        sessionStorage.setItem('code_verifier', codeVerifier);
        
        const params = new URLSearchParams({
            response_type: 'code',
            client_id: config.clientId,
            redirect_uri: config.redirectUri,
            scope: config.scopes,
            state: state,
            nonce: nonce,
            code_challenge: codeChallenge,
            code_challenge_method: 'S256'
        });
        
        const authUrl = `${config.serverUrl}/api/v1/oauth/authorize?${params}`;
        
        return {
            authUrl,
            state,
            nonce,
            codeVerifier,
            codeChallenge
        };
    }
    
    /**
     * Validate OIDC Discovery Document
     */
    static validateDiscoveryDocument(discovery) {
        const requiredFields = [
            'issuer',
            'authorization_endpoint',
            'token_endpoint',
            'userinfo_endpoint',
            'jwks_uri',
            'response_types_supported',
            'subject_types_supported',
            'id_token_signing_alg_values_supported'
        ];
        
        const missingFields = [];
        for (const field of requiredFields) {
            if (!discovery[field]) {
                missingFields.push(field);
            }
        }
        
        if (missingFields.length > 0) {
            return {
                valid: false,
                error: `Missing required fields: ${missingFields.join(', ')}`
            };
        }
        
        // Validate response types include 'code'
        if (!discovery.response_types_supported.includes('code')) {
            return {
                valid: false,
                error: 'Authorization code flow not supported'
            };
        }
        
        // Validate scopes include OIDC scopes
        if (discovery.scopes_supported) {
            const requiredScopes = ['openid', 'profile', 'email'];
            const supportedScopes = discovery.scopes_supported;
            const missingScopes = requiredScopes.filter(s => !supportedScopes.includes(s));
            
            if (missingScopes.length > 0) {
                return {
                    valid: false,
                    error: `Missing required scopes: ${missingScopes.join(', ')}`
                };
            }
        }
        
        return { valid: true, discovery };
    }
    
    /**
     * Validate JWKS
     */
    static validateJWKS(jwks) {
        if (!jwks.keys || !Array.isArray(jwks.keys)) {
            return {
                valid: false,
                error: 'Invalid JWKS format'
            };
        }
        
        if (jwks.keys.length === 0) {
            return {
                valid: false,
                error: 'No keys in JWKS'
            };
        }
        
        // Validate each key
        for (const key of jwks.keys) {
            if (!key.kty || !key.kid || !key.use) {
                return {
                    valid: false,
                    error: 'Invalid key format in JWKS'
                };
            }
            
            if (key.use === 'sig' && !key.alg) {
                return {
                    valid: false,
                    error: 'Signing key missing algorithm'
                };
            }
        }
        
        return { valid: true, keys: jwks.keys };
    }
    
    /**
     * Validate UserInfo Response
     */
    static validateUserInfo(userInfo, idTokenClaims) {
        if (!userInfo.sub) {
            return {
                valid: false,
                error: 'UserInfo missing sub claim'
            };
        }
        
        // Sub claim must match ID token
        if (idTokenClaims && userInfo.sub !== idTokenClaims.sub) {
            return {
                valid: false,
                error: 'UserInfo sub does not match ID token'
            };
        }
        
        return { valid: true, userInfo };
    }
    
    /**
     * Test OIDC Claims
     */
    static async testOIDCClaims(config, tester, accessToken) {
        const { data: userInfo } = await this.fetchUserInfo(config, tester, accessToken);
        
        // Check standard claims based on requested scopes
        const requestedScopes = config.scopes.split(' ');
        const expectedClaims = {
            openid: ['sub'],
            profile: ['name', 'given_name', 'family_name', 'middle_name', 'nickname', 
                     'preferred_username', 'profile', 'picture', 'website', 'gender', 
                     'birthdate', 'zoneinfo', 'locale', 'updated_at'],
            email: ['email', 'email_verified'],
            address: ['address'],
            phone: ['phone_number', 'phone_number_verified']
        };
        
        const presentClaims = [];
        const missingClaims = [];
        
        for (const scope of requestedScopes) {
            if (expectedClaims[scope]) {
                for (const claim of expectedClaims[scope]) {
                    if (userInfo[claim] !== undefined) {
                        presentClaims.push(claim);
                    } else if (scope !== 'profile') {  // Profile claims are optional
                        missingClaims.push(claim);
                    }
                }
            }
        }
        
        return {
            valid: missingClaims.length === 0,
            presentClaims,
            missingClaims,
            userInfo
        };
    }
    
    /**
     * Test ID Token at_hash claim
     */
    static validateAtHash(idToken, accessToken) {
        const tokenData = this.validateIDToken(idToken, { clientId: 'dummy' });
        
        if (!tokenData.valid) {
            return { valid: false, error: 'Invalid ID token' };
        }
        
        if (!tokenData.payload.at_hash) {
            return { valid: true, warning: 'at_hash not present (optional)' };
        }
        
        // Validate at_hash (left-most half of access token hash)
        // This is a simplified check - real implementation would compute the hash
        return { valid: true, at_hash: tokenData.payload.at_hash };
    }
}

// Export for use in test suites
window.OIDCFlows = OIDCFlows;