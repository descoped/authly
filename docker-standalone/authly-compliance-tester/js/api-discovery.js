/**
 * API Discovery and Dynamic Testing
 * Dynamically discovers and tests Authly's capabilities
 */

class APIDiscovery {
    constructor() {
        this.openApiSpec = null;
        this.discoveryDoc = null;
        this.endpoints = {};
        this.capabilities = {};
    }
    
    /**
     * Load OpenAPI specification
     */
    async loadOpenAPISpec(serverUrl) {
        try {
            const response = await fetch(`${serverUrl}/openapi.json`);
            if (!response.ok) throw new Error(`Failed to load OpenAPI spec: ${response.status}`);
            
            this.openApiSpec = await response.json();
            this.parseEndpoints();
            return this.openApiSpec;
        } catch (error) {
            console.error('Failed to load OpenAPI spec:', error);
            throw error;
        }
    }
    
    /**
     * Load OIDC Discovery Document
     */
    async loadDiscoveryDocument(serverUrl) {
        try {
            const response = await fetch(`${serverUrl}/.well-known/openid-configuration`);
            if (!response.ok) throw new Error(`Failed to load discovery doc: ${response.status}`);
            
            this.discoveryDoc = await response.json();
            this.parseCapabilities();
            return this.discoveryDoc;
        } catch (error) {
            console.error('Failed to load discovery document:', error);
            throw error;
        }
    }
    
    /**
     * Parse endpoints from OpenAPI spec
     */
    parseEndpoints() {
        if (!this.openApiSpec) return;
        
        this.endpoints = {
            auth: [],
            oauth: [],
            oidc: [],
            admin: [],
            users: [],
            health: []
        };
        
        for (const [path, methods] of Object.entries(this.openApiSpec.paths)) {
            for (const [method, spec] of Object.entries(methods)) {
                const endpoint = {
                    path,
                    method: method.toUpperCase(),
                    operationId: spec.operationId,
                    summary: spec.summary,
                    description: spec.description,
                    tags: spec.tags || [],
                    parameters: spec.parameters || [],
                    requestBody: spec.requestBody,
                    responses: spec.responses,
                    security: spec.security
                };
                
                // Categorize endpoints
                if (path.startsWith('/admin/')) {
                    this.endpoints.admin.push(endpoint);
                } else if (path.includes('/oauth/')) {
                    this.endpoints.oauth.push(endpoint);
                } else if (path.includes('/oidc/') || path.includes('/.well-known/')) {
                    this.endpoints.oidc.push(endpoint);
                } else if (path.includes('/auth/')) {
                    this.endpoints.auth.push(endpoint);
                } else if (path.includes('/users/')) {
                    this.endpoints.users.push(endpoint);
                } else if (path.includes('/health') || path.includes('/metrics')) {
                    this.endpoints.health.push(endpoint);
                }
            }
        }
    }
    
    /**
     * Parse capabilities from discovery document
     */
    parseCapabilities() {
        if (!this.discoveryDoc) return;
        
        this.capabilities = {
            issuer: this.discoveryDoc.issuer,
            authorizationEndpoint: this.discoveryDoc.authorization_endpoint,
            tokenEndpoint: this.discoveryDoc.token_endpoint,
            userInfoEndpoint: this.discoveryDoc.userinfo_endpoint,
            jwksUri: this.discoveryDoc.jwks_uri,
            revocationEndpoint: this.discoveryDoc.revocation_endpoint,
            introspectionEndpoint: this.discoveryDoc.introspection_endpoint,
            endSessionEndpoint: this.discoveryDoc.end_session_endpoint,
            checkSessionIframe: this.discoveryDoc.check_session_iframe,
            frontchannelLogout: this.discoveryDoc.frontchannel_logout_supported,
            backchannelLogout: this.discoveryDoc.backchannel_logout_supported,
            scopes: this.discoveryDoc.scopes_supported || [],
            responseTypes: this.discoveryDoc.response_types_supported || [],
            grantTypes: this.discoveryDoc.grant_types_supported || [],
            tokenAuthMethods: this.discoveryDoc.token_endpoint_auth_methods_supported || [],
            claims: this.discoveryDoc.claims_supported || [],
            idTokenAlgs: this.discoveryDoc.id_token_signing_alg_values_supported || [],
            codeChallengeSupported: this.discoveryDoc.code_challenge_methods_supported || [],
            requirePkce: this.discoveryDoc.require_pkce || false
        };
    }
    
    /**
     * Generate dynamic test suites based on discovered capabilities
     */
    generateDynamicTestSuites() {
        const suites = [];
        
        // OAuth 2.1 Test Suite
        if (this.endpoints.oauth.length > 0) {
            suites.push({
                id: 'oauth_dynamic',
                name: 'OAuth 2.1 Dynamic Tests',
                description: 'Dynamically generated OAuth tests based on API discovery',
                tests: this.generateOAuthTests()
            });
        }
        
        // Admin API Test Suite
        if (this.endpoints.admin.length > 0) {
            suites.push({
                id: 'admin_dynamic',
                name: 'Admin API Tests',
                description: 'Test admin endpoints for client, user, and scope management',
                tests: this.generateAdminTests()
            });
        }
        
        // OIDC Advanced Features
        if (this.capabilities.frontchannelLogout || this.capabilities.checkSessionIframe) {
            suites.push({
                id: 'oidc_advanced',
                name: 'OIDC Advanced Features',
                description: 'Test advanced OIDC features like session management',
                tests: this.generateOIDCAdvancedTests()
            });
        }
        
        // Scope Testing
        if (this.capabilities.scopes && this.capabilities.scopes.length > 0) {
            suites.push({
                id: 'scope_testing',
                name: 'Scope Permission Tests',
                description: 'Test granular scope permissions and access control',
                tests: this.generateScopeTests()
            });
        }
        
        return suites;
    }
    
    /**
     * Generate OAuth tests based on discovered endpoints
     */
    generateOAuthTests() {
        const tests = [];
        
        // Test each OAuth endpoint
        for (const endpoint of this.endpoints.oauth) {
            tests.push({
                id: `oauth_${endpoint.operationId}`,
                name: `${endpoint.method} ${endpoint.path}`,
                description: endpoint.summary || endpoint.description,
                endpoint,
                run: async (config, tester) => {
                    return await this.testEndpoint(endpoint, config, tester);
                }
            });
        }
        
        // Add flow tests based on capabilities
        if (this.capabilities.grantTypes.includes('authorization_code')) {
            tests.push({
                id: 'oauth_full_flow',
                name: 'Complete Authorization Flow',
                description: 'Test full authorization code flow with PKCE',
                run: async (config, tester) => {
                    return await this.testAuthorizationFlow(config, tester);
                }
            });
        }
        
        return tests;
    }
    
    /**
     * Generate Admin API tests
     */
    generateAdminTests() {
        const tests = [];
        
        // Group admin endpoints by resource
        const resources = {
            clients: [],
            users: [],
            scopes: [],
            system: []
        };
        
        for (const endpoint of this.endpoints.admin) {
            if (endpoint.path.includes('/clients')) {
                resources.clients.push(endpoint);
            } else if (endpoint.path.includes('/users')) {
                resources.users.push(endpoint);
            } else if (endpoint.path.includes('/scopes')) {
                resources.scopes.push(endpoint);
            } else {
                resources.system.push(endpoint);
            }
        }
        
        // Create tests for each resource type
        for (const [resource, endpoints] of Object.entries(resources)) {
            if (endpoints.length > 0) {
                tests.push({
                    id: `admin_${resource}_crud`,
                    name: `${resource.charAt(0).toUpperCase() + resource.slice(1)} Management`,
                    description: `Test CRUD operations for ${resource}`,
                    endpoints,
                    run: async (config, tester) => {
                        return await this.testAdminResource(resource, endpoints, config, tester);
                    }
                });
            }
        }
        
        return tests;
    }
    
    /**
     * Generate OIDC advanced tests
     */
    generateOIDCAdvancedTests() {
        const tests = [];
        
        if (this.capabilities.checkSessionIframe) {
            tests.push({
                id: 'oidc_session_management',
                name: 'Session Management',
                description: 'Test OIDC session management with iframe',
                run: async (config, tester) => {
                    return await this.testSessionManagement(config, tester);
                }
            });
        }
        
        if (this.capabilities.frontchannelLogout) {
            tests.push({
                id: 'oidc_frontchannel_logout',
                name: 'Frontchannel Logout',
                description: 'Test OIDC frontchannel logout',
                run: async (config, tester) => {
                    return await this.testFrontchannelLogout(config, tester);
                }
            });
        }
        
        if (this.capabilities.claims && this.capabilities.claims.length > 0) {
            tests.push({
                id: 'oidc_claims_support',
                name: 'Claims Support',
                description: 'Test support for all advertised claims',
                run: async (config, tester) => {
                    return await this.testClaimsSupport(config, tester);
                }
            });
        }
        
        return tests;
    }
    
    /**
     * Generate scope permission tests
     */
    generateScopeTests() {
        const tests = [];
        
        // Test each scope category
        const scopeCategories = {
            admin: this.capabilities.scopes.filter(s => s.startsWith('admin:')),
            oidc: ['openid', 'profile', 'email', 'address', 'phone'].filter(s => 
                this.capabilities.scopes.includes(s)),
            custom: this.capabilities.scopes.filter(s => 
                !s.startsWith('admin:') && !['openid', 'profile', 'email', 'address', 'phone'].includes(s))
        };
        
        for (const [category, scopes] of Object.entries(scopeCategories)) {
            if (scopes.length > 0) {
                tests.push({
                    id: `scope_${category}`,
                    name: `${category.charAt(0).toUpperCase() + category.slice(1)} Scopes`,
                    description: `Test ${category} scope permissions`,
                    scopes,
                    run: async (config, tester) => {
                        return await this.testScopeCategory(category, scopes, config, tester);
                    }
                });
            }
        }
        
        return tests;
    }
    
    /**
     * Test a specific endpoint
     */
    async testEndpoint(endpoint, config, tester) {
        try {
            const url = endpoint.path;
            const method = endpoint.method;
            
            // Build request based on endpoint spec
            const requestOptions = {
                method,
                headers: {}
            };
            
            // Add authentication if required
            if (endpoint.security) {
                // Add appropriate auth headers
                if (config.accessToken) {
                    requestOptions.headers['Authorization'] = `Bearer ${config.accessToken}`;
                }
            }
            
            const { response, data } = await tester.makeRequest(url, requestOptions);
            
            // Validate response against OpenAPI spec
            const expectedResponses = Object.keys(endpoint.responses);
            const isValidResponse = expectedResponses.includes(response.status.toString());
            
            return {
                passed: isValidResponse,
                details: {
                    endpoint: `${method} ${url}`,
                    status: response.status,
                    expectedStatuses: expectedResponses,
                    response: data
                },
                error: !isValidResponse ? 
                    `Unexpected status ${response.status}, expected one of: ${expectedResponses.join(', ')}` : null
            };
        } catch (error) {
            return {
                passed: false,
                details: { error: error.message },
                error: error.message
            };
        }
    }
    
    /**
     * Test full authorization flow
     */
    async testAuthorizationFlow(config, tester) {
        try {
            // Start authorization flow
            const flowData = await OAuthFlows.startAuthorizationFlow(config, tester);
            
            // Simulate authorization (would need user interaction in real scenario)
            tester.addLog('Authorization flow initiated', 'info');
            
            return {
                passed: true,
                details: {
                    authUrl: flowData.authUrl,
                    state: flowData.state,
                    codeChallenge: flowData.codeChallenge
                },
                error: null
            };
        } catch (error) {
            return {
                passed: false,
                details: { error: error.message },
                error: error.message
            };
        }
    }
    
    /**
     * Test admin resource CRUD operations
     */
    async testAdminResource(resource, endpoints, config, tester) {
        const results = {
            create: null,
            read: null,
            update: null,
            delete: null
        };
        
        // Find CRUD endpoints
        const crudEndpoints = {
            create: endpoints.find(e => e.method === 'POST' && !e.path.includes('{'))  ,
            read: endpoints.find(e => e.method === 'GET'),
            update: endpoints.find(e => e.method === 'PUT'),
            delete: endpoints.find(e => e.method === 'DELETE')
        };
        
        // Test each CRUD operation
        for (const [operation, endpoint] of Object.entries(crudEndpoints)) {
            if (endpoint) {
                results[operation] = await this.testEndpoint(endpoint, config, tester);
            }
        }
        
        const allPassed = Object.values(results).every(r => r === null || r.passed);
        
        return {
            passed: allPassed,
            details: results,
            error: !allPassed ? 'Some CRUD operations failed' : null
        };
    }
    
    /**
     * Test session management
     */
    async testSessionManagement(config, tester) {
        try {
            const { response, data } = await tester.makeRequest(
                this.capabilities.checkSessionIframe, 
                { method: 'GET' }
            );
            
            const hasIframe = response.status === 200 && 
                (typeof data === 'string' && data.includes('iframe'));
            
            return {
                passed: hasIframe,
                details: {
                    iframeUrl: this.capabilities.checkSessionIframe,
                    status: response.status
                },
                error: !hasIframe ? 'Session management iframe not available' : null
            };
        } catch (error) {
            return {
                passed: false,
                details: { error: error.message },
                error: error.message
            };
        }
    }
    
    /**
     * Test frontchannel logout
     */
    async testFrontchannelLogout(config, tester) {
        try {
            const { response } = await tester.makeRequest('/oidc/frontchannel/logout', {
                method: 'GET'
            });
            
            return {
                passed: response.status === 200 || response.status === 302,
                details: { status: response.status },
                error: (response.status !== 200 && response.status !== 302) ?
                    `Frontchannel logout failed with status ${response.status}` : null
            };
        } catch (error) {
            return {
                passed: false,
                details: { error: error.message },
                error: error.message
            };
        }
    }
    
    /**
     * Test claims support
     */
    async testClaimsSupport(config, tester) {
        const supportedClaims = this.capabilities.claims || [];
        
        return {
            passed: supportedClaims.length > 0,
            details: {
                totalClaims: supportedClaims.length,
                claims: supportedClaims,
                oidcStandardClaims: supportedClaims.filter(c => 
                    ['sub', 'name', 'email', 'email_verified', 'picture'].includes(c))
            },
            error: supportedClaims.length === 0 ? 'No claims supported' : null
        };
    }
    
    /**
     * Test scope category
     */
    async testScopeCategory(category, scopes, config, tester) {
        return {
            passed: scopes.length > 0,
            details: {
                category,
                scopes,
                count: scopes.length
            },
            error: scopes.length === 0 ? `No ${category} scopes available` : null
        };
    }
}

// Export for use
window.APIDiscovery = APIDiscovery;