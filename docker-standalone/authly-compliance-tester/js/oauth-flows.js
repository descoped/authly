/**
 * OAuth 2.1 Flow Implementations
 * Handles OAuth 2.1 authorization flows with PKCE
 */

class OAuthFlows {
    /**
     * Start OAuth 2.1 Authorization Code Flow with PKCE
     */
    static async startAuthorizationFlow(config, tester) {
        const state = tester.generateRandomString(16);
        const codeVerifier = tester.generateRandomString(128);
        const codeChallenge = await tester.sha256(codeVerifier);
        
        // Store flow data
        sessionStorage.setItem('oauth_state', state);
        sessionStorage.setItem('code_verifier', codeVerifier);
        
        const params = new URLSearchParams({
            response_type: 'code',
            client_id: config.clientId,
            redirect_uri: config.redirectUri,
            scope: config.scopes,
            state: state,
            code_challenge: codeChallenge,
            code_challenge_method: 'S256'
        });
        
        const authUrl = `${config.serverUrl}/api/v1/oauth/authorize?${params}`;
        
        return {
            authUrl,
            state,
            codeVerifier,
            codeChallenge
        };
    }
    
    /**
     * Exchange authorization code for tokens
     */
    static async exchangeCodeForTokens(config, tester, code) {
        const codeVerifier = sessionStorage.getItem('code_verifier');
        
        const params = new URLSearchParams({
            grant_type: 'authorization_code',
            code: code,
            client_id: config.clientId,
            redirect_uri: config.redirectUri,
            code_verifier: codeVerifier
        });
        
        const { response, data } = await tester.makeRequest('/api/v1/oauth/token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: params.toString()
        });
        
        return { response, data };
    }
    
    /**
     * Refresh access token
     */
    static async refreshAccessToken(config, tester, refreshToken) {
        const params = new URLSearchParams({
            grant_type: 'refresh_token',
            refresh_token: refreshToken,
            client_id: config.clientId
        });
        
        const { response, data } = await tester.makeRequest('/api/v1/oauth/token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: params.toString()
        });
        
        return { response, data };
    }
    
    /**
     * Revoke token
     */
    static async revokeToken(config, tester, token, tokenTypeHint = 'access_token') {
        const params = new URLSearchParams({
            token: token,
            token_type_hint: tokenTypeHint,
            client_id: config.clientId
        });
        
        const { response, data } = await tester.makeRequest('/api/v1/oauth/revoke', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: params.toString()
        });
        
        return { response, data };
    }
    
    /**
     * Test PKCE validation
     */
    static async testPKCEValidation(config, tester) {
        // Test missing PKCE
        const paramsNoPKCE = new URLSearchParams({
            response_type: 'code',
            client_id: config.clientId,
            redirect_uri: config.redirectUri,
            scope: config.scopes,
            state: tester.generateRandomString(16)
        });
        
        const { response: noPKCEResponse } = await tester.makeRequest(
            `/api/v1/oauth/authorize?${paramsNoPKCE}`,
            { method: 'GET' }
        );
        
        // Test invalid challenge method
        const paramsInvalidMethod = new URLSearchParams({
            response_type: 'code',
            client_id: config.clientId,
            redirect_uri: config.redirectUri,
            scope: config.scopes,
            state: tester.generateRandomString(16),
            code_challenge: 'invalid_challenge',
            code_challenge_method: 'plain'  // OAuth 2.1 requires S256
        });
        
        const { response: invalidMethodResponse } = await tester.makeRequest(
            `/api/v1/oauth/authorize?${paramsInvalidMethod}`,
            { method: 'GET' }
        );
        
        return {
            noPKCE: noPKCEResponse.status === 400,
            invalidMethod: invalidMethodResponse.status === 400
        };
    }
    
    /**
     * Test redirect URI validation
     */
    static async testRedirectURIValidation(config, tester) {
        const state = tester.generateRandomString(16);
        const codeVerifier = tester.generateRandomString(128);
        const codeChallenge = await tester.sha256(codeVerifier);
        
        // Test with invalid redirect URI
        const params = new URLSearchParams({
            response_type: 'code',
            client_id: config.clientId,
            redirect_uri: 'http://evil.com/callback',  // Different from registered
            scope: config.scopes,
            state: state,
            code_challenge: codeChallenge,
            code_challenge_method: 'S256'
        });
        
        try {
            const { response } = await tester.makeRequest(
                `/api/v1/oauth/authorize?${params}`,
                { method: 'GET', redirect: 'manual' }
            );
            
            // Should return 400 for invalid redirect URI
            return response.status === 400;
        } catch (error) {
            tester.addLog(`Redirect URI test error: ${error.message}`, 'error');
            return false;
        }
    }
    
    /**
     * Test state parameter validation
     */
    static async testStateParameter(config, tester) {
        const codeVerifier = tester.generateRandomString(128);
        const codeChallenge = await tester.sha256(codeVerifier);
        
        // Test missing state
        const paramsNoState = new URLSearchParams({
            response_type: 'code',
            client_id: config.clientId,
            redirect_uri: config.redirectUri,
            scope: config.scopes,
            code_challenge: codeChallenge,
            code_challenge_method: 'S256'
        });
        
        const { response: noStateResponse } = await tester.makeRequest(
            `/api/v1/oauth/authorize?${paramsNoState}`,
            { method: 'GET' }
        );
        
        // Test with state
        const paramsWithState = new URLSearchParams({
            response_type: 'code',
            client_id: config.clientId,
            redirect_uri: config.redirectUri,
            scope: config.scopes,
            state: tester.generateRandomString(16),
            code_challenge: codeChallenge,
            code_challenge_method: 'S256'
        });
        
        const { response: withStateResponse } = await tester.makeRequest(
            `/api/v1/oauth/authorize?${paramsWithState}`,
            { method: 'GET' }
        );
        
        return {
            stateRequired: noStateResponse.status === 400,
            statePreserved: withStateResponse.status === 200 || withStateResponse.status === 302
        };
    }
    
    /**
     * Test authorization code expiration
     */
    static async testCodeExpiration(config, tester, code) {
        // Wait for code to expire (typically 10 minutes, but we'll test immediate)
        await new Promise(resolve => setTimeout(resolve, 11 * 60 * 1000));
        
        const codeVerifier = sessionStorage.getItem('code_verifier');
        const params = new URLSearchParams({
            grant_type: 'authorization_code',
            code: code,
            client_id: config.clientId,
            redirect_uri: config.redirectUri,
            code_verifier: codeVerifier
        });
        
        const { response } = await tester.makeRequest('/api/v1/oauth/token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: params.toString()
        });
        
        return response.status === 400;
    }
    
    /**
     * Test refresh token rotation
     */
    static async testRefreshTokenRotation(config, tester, initialRefreshToken) {
        // Use refresh token
        const { data: firstRefresh } = await this.refreshAccessToken(config, tester, initialRefreshToken);
        
        if (!firstRefresh.refresh_token || firstRefresh.refresh_token === initialRefreshToken) {
            return false;  // No rotation
        }
        
        // Try to use old refresh token (should fail)
        try {
            const { response } = await this.refreshAccessToken(config, tester, initialRefreshToken);
            return response.status === 400;  // Old token should be invalid
        } catch {
            return true;  // Request failed as expected
        }
    }
}

// Export for use in test suites
window.OAuthFlows = OAuthFlows;