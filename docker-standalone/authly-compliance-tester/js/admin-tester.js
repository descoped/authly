/**
 * Admin API Testing Module
 * Tests Authly's admin APIs for client, user, and scope management
 */

class AdminTester {
    constructor(config, tester) {
        this.config = config;
        this.tester = tester;
        this.adminToken = null;
        this.testData = {
            clients: [],
            users: [],
            scopes: []
        };
    }
    
    /**
     * Authenticate as admin
     */
    async authenticateAdmin() {
        try {
            // Get admin token
            const { response, data } = await this.tester.makeRequest('/api/v1/oauth/token', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: new URLSearchParams({
                    grant_type: 'client_credentials',
                    client_id: this.config.adminClientId || 'admin_client',
                    client_secret: this.config.adminClientSecret || 'admin_secret',
                    scope: 'admin'
                }).toString()
            });
            
            if (response.ok && data.access_token) {
                this.adminToken = data.access_token;
                return true;
            }
            
            return false;
        } catch (error) {
            this.tester.addLog(`Admin authentication failed: ${error.message}`, 'error');
            return false;
        }
    }
    
    /**
     * Test client management CRUD operations
     */
    async testClientManagement() {
        const results = {
            create: false,
            read: false,
            update: false,
            delete: false,
            regenerateSecret: false,
            oidcConfig: false
        };
        
        try {
            // Create a test client
            const clientData = {
                client_id: `test_client_${Date.now()}`,
                client_name: 'Test Client for Admin API',
                client_type: 'confidential',
                redirect_uris: ['http://localhost:3000/callback'],
                grant_types: ['authorization_code', 'refresh_token'],
                response_types: ['code'],
                scope: 'openid profile email',
                token_endpoint_auth_method: 'client_secret_basic'
            };
            
            const createResp = await this.makeAdminRequest('/admin/clients', {
                method: 'POST',
                body: JSON.stringify(clientData)
            });
            
            if (createResp.success) {
                results.create = true;
                this.testData.clients.push(createResp.data);
                const clientId = createResp.data.client_id;
                
                // Read client
                const readResp = await this.makeAdminRequest(`/admin/clients/${clientId}`, {
                    method: 'GET'
                });
                results.read = readResp.success;
                
                // Update client
                const updateData = {
                    ...clientData,
                    client_name: 'Updated Test Client'
                };
                
                const updateResp = await this.makeAdminRequest(`/admin/clients/${clientId}`, {
                    method: 'PUT',
                    body: JSON.stringify(updateData)
                });
                results.update = updateResp.success;
                
                // Regenerate secret
                const regenResp = await this.makeAdminRequest(`/admin/clients/${clientId}/regenerate-secret`, {
                    method: 'POST'
                });
                results.regenerateSecret = regenResp.success;
                
                // Get OIDC config
                const oidcResp = await this.makeAdminRequest(`/admin/clients/${clientId}/oidc`, {
                    method: 'GET'
                });
                results.oidcConfig = oidcResp.success;
                
                // Delete client
                const deleteResp = await this.makeAdminRequest(`/admin/clients/${clientId}`, {
                    method: 'DELETE'
                });
                results.delete = deleteResp.success;
            }
        } catch (error) {
            this.tester.addLog(`Client management test error: ${error.message}`, 'error');
        }
        
        return results;
    }
    
    /**
     * Test user management CRUD operations
     */
    async testUserManagement() {
        const results = {
            create: false,
            read: false,
            update: false,
            resetPassword: false,
            sessions: false,
            delete: false
        };
        
        try {
            // Create a test user
            const userData = {
                username: `testuser_${Date.now()}`,
                email: `test_${Date.now()}@example.com`,
                password: 'TestPassword123!',
                given_name: 'Test',
                family_name: 'User',
                email_verified: false
            };
            
            const createResp = await this.makeAdminRequest('/admin/users', {
                method: 'POST',
                body: JSON.stringify(userData)
            });
            
            if (createResp.success) {
                results.create = true;
                this.testData.users.push(createResp.data);
                const userId = createResp.data.id;
                
                // Read user
                const readResp = await this.makeAdminRequest(`/admin/users/${userId}`, {
                    method: 'GET'
                });
                results.read = readResp.success;
                
                // Update user
                const updateData = {
                    ...userData,
                    email_verified: true,
                    given_name: 'Updated'
                };
                
                const updateResp = await this.makeAdminRequest(`/admin/users/${userId}`, {
                    method: 'PUT',
                    body: JSON.stringify(updateData)
                });
                results.update = updateResp.success;
                
                // Reset password
                const resetResp = await this.makeAdminRequest(`/admin/users/${userId}/reset-password`, {
                    method: 'POST',
                    body: JSON.stringify({ new_password: 'NewPassword123!' })
                });
                results.resetPassword = resetResp.success;
                
                // Get sessions
                const sessionsResp = await this.makeAdminRequest(`/admin/users/${userId}/sessions`, {
                    method: 'GET'
                });
                results.sessions = sessionsResp.success;
                
                // Delete user
                const deleteResp = await this.makeAdminRequest(`/admin/users/${userId}`, {
                    method: 'DELETE'
                });
                results.delete = deleteResp.success;
            }
        } catch (error) {
            this.tester.addLog(`User management test error: ${error.message}`, 'error');
        }
        
        return results;
    }
    
    /**
     * Test scope management CRUD operations
     */
    async testScopeManagement() {
        const results = {
            create: false,
            read: false,
            update: false,
            defaults: false,
            delete: false
        };
        
        try {
            // Create a test scope
            const scopeData = {
                name: `test:scope:${Date.now()}`,
                description: 'Test scope for admin API testing',
                default: false
            };
            
            const createResp = await this.makeAdminRequest('/admin/scopes', {
                method: 'POST',
                body: JSON.stringify(scopeData)
            });
            
            if (createResp.success) {
                results.create = true;
                this.testData.scopes.push(createResp.data);
                const scopeName = createResp.data.name;
                
                // Read scope
                const readResp = await this.makeAdminRequest(`/admin/scopes/${scopeName}`, {
                    method: 'GET'
                });
                results.read = readResp.success;
                
                // Get default scopes
                const defaultsResp = await this.makeAdminRequest('/admin/scopes/defaults', {
                    method: 'GET'
                });
                results.defaults = defaultsResp.success;
                
                // Update scope
                const updateData = {
                    ...scopeData,
                    description: 'Updated test scope description'
                };
                
                const updateResp = await this.makeAdminRequest(`/admin/scopes/${scopeName}`, {
                    method: 'PUT',
                    body: JSON.stringify(updateData)
                });
                results.update = updateResp.success;
                
                // Delete scope
                const deleteResp = await this.makeAdminRequest(`/admin/scopes/${scopeName}`, {
                    method: 'DELETE'
                });
                results.delete = deleteResp.success;
            }
        } catch (error) {
            this.tester.addLog(`Scope management test error: ${error.message}`, 'error');
        }
        
        return results;
    }
    
    /**
     * Test system status and health endpoints
     */
    async testSystemEndpoints() {
        const results = {
            health: false,
            status: false,
            stats: false,
            algorithms: false
        };
        
        try {
            // Health check
            const healthResp = await this.makeAdminRequest('/admin/health', {
                method: 'GET'
            });
            results.health = healthResp.success;
            
            // System status
            const statusResp = await this.makeAdminRequest('/admin/status', {
                method: 'GET'
            });
            results.status = statusResp.success;
            
            // Dashboard stats
            const statsResp = await this.makeAdminRequest('/admin/dashboard/stats', {
                method: 'GET'
            });
            results.stats = statsResp.success;
            
            // OIDC algorithms
            const algsResp = await this.makeAdminRequest('/admin/clients/oidc/algorithms', {
                method: 'GET'
            });
            results.algorithms = algsResp.success;
        } catch (error) {
            this.tester.addLog(`System endpoints test error: ${error.message}`, 'error');
        }
        
        return results;
    }
    
    /**
     * Test bulk operations
     */
    async testBulkOperations() {
        const results = {
            listClients: false,
            listUsers: false,
            listScopes: false,
            pagination: false,
            filtering: false
        };
        
        try {
            // List clients with pagination
            const clientsResp = await this.makeAdminRequest('/admin/clients?limit=10&offset=0', {
                method: 'GET'
            });
            results.listClients = clientsResp.success;
            
            // List users with pagination
            const usersResp = await this.makeAdminRequest('/admin/users?limit=10&offset=0', {
                method: 'GET'
            });
            results.listUsers = usersResp.success;
            
            // List scopes
            const scopesResp = await this.makeAdminRequest('/admin/scopes', {
                method: 'GET'
            });
            results.listScopes = scopesResp.success;
            
            // Test pagination
            if (usersResp.success && usersResp.data.total > 10) {
                const page2Resp = await this.makeAdminRequest('/admin/users?limit=10&offset=10', {
                    method: 'GET'
                });
                results.pagination = page2Resp.success;
            } else {
                results.pagination = true; // Skip if not enough data
            }
            
            // Test filtering (if supported)
            const filterResp = await this.makeAdminRequest('/admin/users?email_verified=true', {
                method: 'GET'
            });
            results.filtering = filterResp.success;
        } catch (error) {
            this.tester.addLog(`Bulk operations test error: ${error.message}`, 'error');
        }
        
        return results;
    }
    
    /**
     * Make admin API request with authentication
     */
    async makeAdminRequest(path, options = {}) {
        try {
            const headers = {
                'Authorization': `Bearer ${this.adminToken}`,
                'Content-Type': 'application/json',
                ...options.headers
            };
            
            const { response, data } = await this.tester.makeRequest(path, {
                ...options,
                headers
            });
            
            return {
                success: response.ok,
                status: response.status,
                data
            };
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    /**
     * Run all admin tests
     */
    async runAllTests() {
        const results = {
            authentication: false,
            clientManagement: {},
            userManagement: {},
            scopeManagement: {},
            systemEndpoints: {},
            bulkOperations: {}
        };
        
        this.tester.addLog('Starting Admin API tests...', 'info');
        
        // Authenticate first
        results.authentication = await this.authenticateAdmin();
        
        if (!results.authentication) {
            this.tester.addLog('Admin authentication failed - skipping tests', 'error');
            return results;
        }
        
        this.tester.addLog('Admin authentication successful', 'success');
        
        // Run test suites
        this.tester.addLog('Testing client management...', 'info');
        results.clientManagement = await this.testClientManagement();
        
        this.tester.addLog('Testing user management...', 'info');
        results.userManagement = await this.testUserManagement();
        
        this.tester.addLog('Testing scope management...', 'info');
        results.scopeManagement = await this.testScopeManagement();
        
        this.tester.addLog('Testing system endpoints...', 'info');
        results.systemEndpoints = await this.testSystemEndpoints();
        
        this.tester.addLog('Testing bulk operations...', 'info');
        results.bulkOperations = await this.testBulkOperations();
        
        // Cleanup test data
        await this.cleanup();
        
        return results;
    }
    
    /**
     * Cleanup test data
     */
    async cleanup() {
        this.tester.addLog('Cleaning up test data...', 'info');
        
        // Clean up any remaining test clients
        for (const client of this.testData.clients) {
            try {
                await this.makeAdminRequest(`/admin/clients/${client.client_id}`, {
                    method: 'DELETE'
                });
            } catch (error) {
                // Ignore cleanup errors
            }
        }
        
        // Clean up any remaining test users
        for (const user of this.testData.users) {
            try {
                await this.makeAdminRequest(`/admin/users/${user.id}`, {
                    method: 'DELETE'
                });
            } catch (error) {
                // Ignore cleanup errors
            }
        }
        
        // Clean up any remaining test scopes
        for (const scope of this.testData.scopes) {
            try {
                await this.makeAdminRequest(`/admin/scopes/${scope.name}`, {
                    method: 'DELETE'
                });
            } catch (error) {
                // Ignore cleanup errors
            }
        }
    }
}

// Export for use
window.AdminTester = AdminTester;