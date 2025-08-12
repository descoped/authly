/**
 * Admin Client Management
 * Handles OAuth client creation via Admin API using admin tokens
 */

class AdminClient {
    constructor(config, tester) {
        this.config = config;
        this.tester = tester;
        this.adminToken = null;
        this.testClient = null;
        this.logger = new Logger();
        this.discovery = new DiscoveryService(this.logger);
    }
    
    /**
     * Load admin tokens from bootstrap configuration
     */
    async loadAdminTokens() {
        this.logger.section('Loading Admin Tokens');
        
        try {
            // Load tokens saved by bootstrap script
            const response = await fetch('/data/admin-tokens.json');
            if (!response.ok) {
                throw new Error(`Failed to load admin tokens: ${response.status}`);
            }
            
            const tokens = await response.json();
            this.adminToken = tokens.access_token;
            
            this.logger.success('Admin tokens loaded successfully');
            this.logger.debug('Token type: Bearer');
            this.logger.debug(`Scope: ${tokens.scope}`);
            
            return true;
        } catch (error) {
            this.logger.error('Failed to load admin tokens:', error.message);
            this.logger.info('Run bootstrap script to generate admin tokens');
            return false;
        }
    }
    
    /**
     * Load test client created during bootstrap
     */
    async loadTestClient() {
        try {
            const response = await fetch('/data/test-client.json');
            if (!response.ok) {
                throw new Error(`Failed to load test client: ${response.status}`);
            }
            
            this.testClient = await response.json();
            return this.testClient;
        } catch (error) {
            this.logger.error('Failed to load test client:', error.message);
            return null;
        }
    }
    
    /**
     * Show current client info
     */
    async showClientInfo() {
        this.logger.section('OAuth Client Information');
        
        // Try to load test client from bootstrap
        const testClient = await this.loadTestClient();
        
        if (testClient && testClient.client_id) {
            this.logger.success('Test client loaded from bootstrap:');
            this.logger.info(`Client ID: ${testClient.client_id}`);
            this.logger.info(`Client Name: ${testClient.client_name}`);
            this.logger.info(`Client Type: ${testClient.client_type}`);
            this.logger.info(`Redirect URIs: ${testClient.redirect_uris?.join(', ')}`);
            this.logger.info(`Scopes: ${testClient.scope}`);
            
            // Update the UI with client info
            if (this.tester) {
                this.tester.config.clientId = testClient.client_id;
                this.tester.config.clientSecret = ''; // Public client has no secret
                this.tester.updateConfigUI();
            }
            
            return testClient;
        } else {
            this.logger.warning('No test client found from bootstrap');
            this.logger.info('Client can be created via API using admin tokens');
            
            // Check if we have admin tokens
            const hasTokens = await this.loadAdminTokens();
            if (hasTokens) {
                this.logger.success('Admin tokens available for client management');
                this.logger.info('Click "Create Test Client" button to create a new client');
            } else {
                this.logger.error('No admin tokens available');
                this.logger.info('Bootstrap needs to run to generate admin tokens');
            }
            
            return null;
        }
    }
    
    /**
     * Create a test OAuth client via API
     */
    async createTestClient(clientConfig = {}) {
        this.logger.subsection('Creating OAuth Client');
        
        // First ensure we have admin token
        if (!this.adminToken) {
            this.logger.info('Loading admin tokens...');
            const loaded = await this.loadAdminTokens();
            if (!loaded) {
                this.logger.error('Cannot create client without admin tokens');
                return null;
            }
        }
        
        const clientsEndpoint = '/api/v1/admin/clients';
        this.logger.debug(`Endpoint: POST ${clientsEndpoint}`);
        this.logger.debug('Authorization: Bearer token');
        
        const clientData = {
            client_name: clientConfig.name || `Compliance Tester Client ${Date.now()}`,
            client_type: clientConfig.type || 'public',
            redirect_uris: clientConfig.redirect_uris || [
                `http://localhost:8080/callback`,
                `http://${window.location.hostname}:${window.location.port || '8080'}/callback`
            ],
            scope: clientConfig.scope || 'openid profile email',
            grant_types: clientConfig.grant_types || ['authorization_code', 'refresh_token'],
            require_pkce: clientConfig.require_pkce !== false
        };
        
        this.logger.debug('Request payload:', clientData);
        
        try {
            const response = await fetch(clientsEndpoint, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${this.adminToken}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(clientData)
            });
            
            const data = await response.json().catch(() => null);
            this.logger.logHTTP('POST', clientsEndpoint, {
                headers: {
                    'Authorization': `Bearer ${this.adminToken.substring(0, 20)}...[masked]`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(clientData)
            }, response, data);
            
            if (response.status === 201 || response.status === 200) {
                this.logger.success('OAuth client created successfully');
                this.logger.success(`Client ID: ${data.client_id}`);
                this.logger.info(`Client name: ${data.client_name}`);
                this.logger.info(`Client type: ${data.client_type}`);
                this.logger.info(`Grant types: ${data.grant_types?.join(', ') || 'N/A'}`);
                this.logger.info(`Redirect URIs: ${data.redirect_uris?.join(', ') || 'N/A'}`);
                if (data.client_secret) {
                    this.logger.info(`Client secret: ${data.client_secret}`);
                }
                
                // Update the tester config
                if (this.tester) {
                    this.tester.config.clientId = data.client_id;
                    this.tester.config.clientSecret = data.client_secret || '';
                    this.tester.updateConfigUI();
                }
                
                return data;
            } else {
                this.logger.error(`Failed to create client: ${response.status} ${response.statusText}`);
                if (data?.error || data?.detail) {
                    this.logger.error(data.error || data.detail);
                }
                return null;
            }
        } catch (error) {
            this.logger.error('Client creation request failed:', error.message);
            return null;
        }
    }
}