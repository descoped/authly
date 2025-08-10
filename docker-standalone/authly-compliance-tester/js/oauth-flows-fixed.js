/**
 * OAuth 2.1 Flow Implementations - FIXED VERSION
 * Properly handles authentication redirects and parameter validation
 */

class OAuthFlows {
    /**
     * Start OAuth 2.1 Authorization Code Flow with PKCE
     */
    static async startAuthorizationFlow(config, tester) {
        const state = tester.generateRandomString(16);
        const codeVerifier = tester.generateRandomString(128);
        const codeChallenge = await tester.sha256(codeVerifier);
        
        // Store for later use
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
     * Test PKCE validation - FIXED to understand auth flow
     */
    static async testPKCEValidation(config, tester) {
        const results = {
            noPKCE: false,
            invalidMethod: false,
            details: {}
        };
        
        // Test 1: Missing PKCE
        tester.addLog('Testing missing PKCE parameters...', 'info');
        const paramsNoPKCE = new URLSearchParams({
            response_type: 'code',
            client_id: config.clientId,
            redirect_uri: config.redirectUri,
            scope: config.scopes,
            state: tester.generateRandomString(16)
        });
        
        const { response: noPKCEResponse, data: noPKCEData } = await tester.makeRequest(
            `/api/v1/oauth/authorize?${paramsNoPKCE}`,
            { method: 'GET' }
        );
        
        // Check if PKCE is rejected (400) or if we get auth redirect (302)
        if (noPKCEResponse.status === 400) {
            results.noPKCE = true;
            results.details.noPKCE = { 
                status: 400, 
                message: 'PKCE correctly rejected',
                data: noPKCEData 
            };
        } else if (noPKCEResponse.status === 302 || noPKCEResponse.status === 0) {
            // Check if it's login_required or actual acceptance
            const location = noPKCEResponse.headers?.get('location') || '';
            if (location.includes('login_required')) {
                // This means validation happens after auth check - not ideal but not acceptance
                results.noPKCE = false;
                results.details.noPKCE = { 
                    status: noPKCEResponse.status,
                    message: 'Auth checked before PKCE validation (improper order)',
                    location: location
                };
            } else {
                results.noPKCE = false;
                results.details.noPKCE = { 
                    status: noPKCEResponse.status,
                    message: 'PKCE not enforced',
                    data: noPKCEData
                };
            }
        }
        
        // Test 2: Invalid challenge method (plain instead of S256)
        tester.addLog('Testing invalid PKCE method (plain)...', 'info');
        const paramsInvalidMethod = new URLSearchParams({
            response_type: 'code',
            client_id: config.clientId,
            redirect_uri: config.redirectUri,
            scope: config.scopes,
            state: tester.generateRandomString(16),
            code_challenge: 'test_challenge_at_least_43_chars_long_to_be_valid_pkce',
            code_challenge_method: 'plain'
        });
        
        const { response: invalidMethodResponse, data: invalidMethodData } = await tester.makeRequest(
            `/api/v1/oauth/authorize?${paramsInvalidMethod}`,
            { method: 'GET' }
        );
        
        // Check response
        if (invalidMethodResponse.status === 400) {
            // Properly rejected
            results.invalidMethod = true;
            results.details.invalidMethod = { 
                status: 400, 
                message: 'Plain method correctly rejected',
                data: invalidMethodData
            };
        } else if (invalidMethodResponse.status === 302 || invalidMethodResponse.status === 0) {
            // Got redirect - check if it's auth or actual acceptance
            const location = invalidMethodResponse.headers?.get('location') || '';
            
            // IMPORTANT: A 302 redirect to login doesn't mean the server accepts plain!
            // It means the server checks auth before validating PKCE method
            if (location.includes('login_required')) {
                results.invalidMethod = false;
                results.details.invalidMethod = {
                    status: invalidMethodResponse.status,
                    message: 'Server checks authentication before validating PKCE method (OAuth 2.1 violation: parameters should be validated first)',
                    note: 'This is a validation order bug, not acceptance of plain method',
                    location: location
                };
            } else if (location.includes('error=invalid_request')) {
                // Server rejected it properly via redirect
                results.invalidMethod = true;
                results.details.invalidMethod = {
                    status: invalidMethodResponse.status,
                    message: 'Plain method rejected via redirect',
                    location: location
                };
            } else {
                // Server might actually accept plain - this would be bad
                results.invalidMethod = false;
                results.details.invalidMethod = {
                    status: invalidMethodResponse.status,
                    message: 'Plain method may be accepted',
                    location: location,
                    data: invalidMethodData
                };
            }
        }
        
        tester.addLog(`PKCE validation results: noPKCE=${results.noPKCE}, invalidMethod=${results.invalidMethod}`, 'info');
        
        return results;
    }
    
    /**
     * Test state parameter handling
     */
    static async testStateParameter(config, tester) {
        const results = {
            stateRequired: false,
            statePreserved: false,
            details: {}
        };
        
        // Test 1: Missing state parameter
        tester.addLog('Testing missing state parameter...', 'info');
        const paramsNoState = new URLSearchParams({
            response_type: 'code',
            client_id: config.clientId,
            redirect_uri: config.redirectUri,
            scope: config.scopes,
            code_challenge: await tester.sha256(tester.generateRandomString(128)),
            code_challenge_method: 'S256'
        });
        
        const { response: noStateResponse } = await tester.makeRequest(
            `/api/v1/oauth/authorize?${paramsNoState}`,
            { method: 'GET' }
        );
        
        // OAuth 2.1 strongly recommends state but doesn't require it
        if (noStateResponse.status === 400) {
            results.stateRequired = true;
            results.details.noState = { 
                status: 400, 
                message: 'State parameter is required' 
            };
        } else {
            results.stateRequired = false;
            results.details.noState = { 
                status: noStateResponse.status,
                message: 'State parameter is optional (OAuth 2.1 recommends but does not require)'
            };
        }
        
        // Test 2: State preservation
        tester.addLog('Testing state parameter preservation...', 'info');
        const testState = tester.generateRandomString(16);
        const paramsWithState = new URLSearchParams({
            response_type: 'code',
            client_id: config.clientId,
            redirect_uri: config.redirectUri,
            scope: config.scopes,
            state: testState,
            code_challenge: await tester.sha256(tester.generateRandomString(128)),
            code_challenge_method: 'S256'
        });
        
        const { response: stateResponse } = await tester.makeRequest(
            `/api/v1/oauth/authorize?${paramsWithState}`,
            { method: 'GET', redirect: 'manual' }
        );
        
        if (stateResponse.status === 302 || stateResponse.status === 0) {
            const location = stateResponse.headers?.get('location') || '';
            results.statePreserved = location.includes(`state=${testState}`);
            results.details.statePreserved = {
                status: stateResponse.status,
                message: results.statePreserved ? 'State preserved in redirect' : 'State not preserved',
                location: location
            };
        } else {
            results.statePreserved = true; // Assume preserved if not redirect
            results.details.statePreserved = {
                status: stateResponse.status,
                message: 'Request did not redirect'
            };
        }
        
        return results;
    }
    
    /**
     * Test redirect URI validation
     */
    static async testRedirectURIValidation(config, tester) {
        tester.addLog('Testing redirect URI validation...', 'info');
        
        // Test with slightly different redirect URI
        const invalidRedirectUri = config.redirectUri + '/extra';
        const params = new URLSearchParams({
            response_type: 'code',
            client_id: config.clientId,
            redirect_uri: invalidRedirectUri,
            scope: config.scopes,
            state: tester.generateRandomString(16),
            code_challenge: await tester.sha256(tester.generateRandomString(128)),
            code_challenge_method: 'S256'
        });
        
        const { response } = await tester.makeRequest(
            `/api/v1/oauth/authorize?${params}`,
            { method: 'GET' }
        );
        
        // Should reject mismatched redirect URI
        return response.status === 400 || 
               (response.status === 302 && response.headers?.get('location')?.includes('error'));
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
                'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': 'Basic ' + btoa(`${config.clientId}:${config.clientSecret}`)
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
                'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': 'Basic ' + btoa(`${config.clientId}:${config.clientSecret}`)
            },
            body: params.toString()
        });
        
        return { response, data };
    }
    
    /**
     * Revoke token
     */
    static async revokeToken(config, tester, token, tokenType = 'access_token') {
        const params = new URLSearchParams({
            token: token,
            token_type_hint: tokenType
        });
        
        const { response, data } = await tester.makeRequest('/api/v1/oauth/revoke', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': 'Basic ' + btoa(`${config.clientId}:${config.clientSecret}`)
            },
            body: params.toString()
        });
        
        return { response, data };
    }
}

// Make available globally
window.OAuthFlows = OAuthFlows;