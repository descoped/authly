/**
 * OpenID Discovery Service
 * Dynamically discovers and caches OAuth/OIDC endpoints
 */

class DiscoveryService {
    constructor(logger) {
        this.logger = logger || new Logger();
        this.config = null;
        this.endpoints = {};
        this.cacheExpiry = null;
        this.cacheDuration = 3600000; // 1 hour
    }

    /**
     * Get discovered configuration, fetching if needed
     */
    async getConfiguration(forceRefresh = false) {
        if (!forceRefresh && this.config && this.cacheExpiry && Date.now() < this.cacheExpiry) {
            this.logger.debug('Using cached discovery configuration', {
                expiresIn: Math.round((this.cacheExpiry - Date.now()) / 1000) + 's'
            });
            return this.config;
        }

        return await this.discover();
    }

    /**
     * Discover OAuth/OIDC endpoints from well-known URL
     */
    async discover() {
        this.logger.section('OpenID Connect Discovery');
        
        const discoveryUrl = '/.well-known/openid-configuration';
        this.logger.info(`Fetching discovery document from ${discoveryUrl}`);

        try {
            const response = await fetch(discoveryUrl);
            const data = await response.json();

            this.logger.logHTTP('GET', discoveryUrl, {}, response, data);

            if (!response.ok) {
                throw new Error(`Discovery failed: ${response.status} ${response.statusText}`);
            }

            // Store configuration
            this.config = data;
            this.cacheExpiry = Date.now() + this.cacheDuration;

            // Parse and store endpoints
            this.parseEndpoints(data);

            // Log discovered endpoints
            this.logDiscoveredEndpoints();

            return this.config;
        } catch (error) {
            this.logger.error('Failed to fetch discovery document', {
                error: error.message,
                url: discoveryUrl
            });
            
            // Fall back to default endpoints
            this.useDefaultEndpoints();
            return this.config;
        }
    }

    /**
     * Parse endpoints from discovery document
     */
    parseEndpoints(config) {
        // OAuth 2.0 endpoints
        this.endpoints.authorization = config.authorization_endpoint;
        this.endpoints.token = config.token_endpoint;
        this.endpoints.revocation = config.revocation_endpoint;
        this.endpoints.introspection = config.introspection_endpoint;
        this.endpoints.device_authorization = config.device_authorization_endpoint;

        // OIDC endpoints
        this.endpoints.userinfo = config.userinfo_endpoint;
        this.endpoints.jwks = config.jwks_uri;
        this.endpoints.registration = config.registration_endpoint;
        this.endpoints.end_session = config.end_session_endpoint;

        // Additional metadata
        this.endpoints.issuer = config.issuer;
        this.endpoints.scopes_supported = config.scopes_supported || [];
        this.endpoints.response_types_supported = config.response_types_supported || [];
        this.endpoints.grant_types_supported = config.grant_types_supported || [];
        this.endpoints.code_challenge_methods_supported = config.code_challenge_methods_supported || [];

        this.logger.success('Successfully parsed discovery endpoints', {
            endpointCount: Object.keys(this.endpoints).length
        });
    }

    /**
     * Log discovered endpoints
     */
    logDiscoveredEndpoints() {
        this.logger.subsection('Discovered Endpoints');
        
        // Core OAuth endpoints
        this.logger.info('OAuth 2.0 Endpoints:');
        this.logger.indent(`Authorization: ${this.endpoints.authorization || 'Not found'}`);
        this.logger.indent(`Token: ${this.endpoints.token || 'Not found'}`);
        this.logger.indent(`Revocation: ${this.endpoints.revocation || 'Not found'}`);
        this.logger.indent(`Introspection: ${this.endpoints.introspection || 'Not found'}`);
        
        // OIDC endpoints
        this.logger.info('OIDC Endpoints:');
        this.logger.indent(`UserInfo: ${this.endpoints.userinfo || 'Not found'}`);
        this.logger.indent(`JWKS: ${this.endpoints.jwks || 'Not found'}`);
        this.logger.indent(`End Session: ${this.endpoints.end_session || 'Not found'}`);
        
        // Capabilities
        this.logger.info('Capabilities:');
        this.logger.indent(`PKCE Methods: ${this.endpoints.code_challenge_methods_supported?.join(', ') || 'None'}`);
        this.logger.indent(`Grant Types: ${this.endpoints.grant_types_supported?.join(', ') || 'None'}`);
        this.logger.indent(`Response Types: ${this.endpoints.response_types_supported?.join(', ') || 'None'}`);
    }

    /**
     * Fall back to default endpoints if discovery fails
     */
    useDefaultEndpoints() {
        this.logger.warning('Using default endpoint configuration');
        
        this.config = {
            issuer: window.location.origin,
            authorization_endpoint: '/auth/authorize',
            token_endpoint: '/oauth/token',
            userinfo_endpoint: '/oidc/userinfo',
            jwks_uri: '/oidc/jwks',
            revocation_endpoint: '/oauth/revoke',
            introspection_endpoint: '/oauth/introspect',
            end_session_endpoint: '/oidc/logout',
            scopes_supported: ['openid', 'profile', 'email'],
            response_types_supported: ['code'],
            grant_types_supported: ['authorization_code', 'refresh_token', 'password'],
            code_challenge_methods_supported: ['S256']
        };

        this.parseEndpoints(this.config);
    }

    /**
     * Get specific endpoint URL
     */
    getEndpoint(name) {
        if (!this.endpoints[name]) {
            this.logger.warning(`Endpoint '${name}' not found in discovery`);
        }
        return this.endpoints[name];
    }

    /**
     * Check if a grant type is supported
     */
    isGrantTypeSupported(grantType) {
        const supported = this.endpoints.grant_types_supported?.includes(grantType) || false;
        if (!supported) {
            this.logger.warning(`Grant type '${grantType}' not supported`, {
                supported: this.endpoints.grant_types_supported
            });
        }
        return supported;
    }

    /**
     * Check if PKCE method is supported
     */
    isPKCEMethodSupported(method) {
        const supported = this.endpoints.code_challenge_methods_supported?.includes(method) || false;
        if (!supported) {
            this.logger.warning(`PKCE method '${method}' not supported`, {
                supported: this.endpoints.code_challenge_methods_supported
            });
        }
        return supported;
    }

    /**
     * Build authorization URL with parameters
     */
    buildAuthorizationUrl(params) {
        const authEndpoint = this.getEndpoint('authorization');
        if (!authEndpoint) {
            throw new Error('Authorization endpoint not found');
        }

        const url = new URL(authEndpoint, window.location.origin);
        Object.entries(params).forEach(([key, value]) => {
            if (value !== undefined && value !== null) {
                url.searchParams.set(key, value);
            }
        });

        this.logger.debug('Built authorization URL', {
            endpoint: authEndpoint,
            params,
            fullUrl: url.toString()
        });

        return url.toString();
    }

    /**
     * Make authenticated API request using discovered endpoints
     */
    async makeRequest(endpointName, options = {}) {
        const endpoint = this.getEndpoint(endpointName);
        if (!endpoint) {
            throw new Error(`Endpoint '${endpointName}' not found`);
        }

        const url = new URL(endpoint, window.location.origin);
        
        this.logger.debug(`Making request to ${endpointName}`, {
            url: url.toString(),
            method: options.method || 'GET'
        });

        const response = await fetch(url, options);
        const data = await response.json().catch(() => null);

        this.logger.logHTTP(options.method || 'GET', url.toString(), options, response, data);

        return { response, data };
    }

    /**
     * Validate discovery configuration
     */
    validateConfiguration() {
        const required = ['authorization_endpoint', 'token_endpoint'];
        const missing = required.filter(field => !this.config[field]);
        
        if (missing.length > 0) {
            this.logger.error('Missing required discovery fields', { missing });
            return false;
        }

        // Check OAuth 2.1 compliance
        if (!this.isPKCEMethodSupported('S256')) {
            this.logger.warning('S256 PKCE not supported - OAuth 2.1 compliance issue');
        }

        return true;
    }

    /**
     * Clear cached configuration
     */
    clearCache() {
        this.config = null;
        this.endpoints = {};
        this.cacheExpiry = null;
        this.logger.info('Cleared discovery cache');
    }
}

// Export for use
window.DiscoveryService = DiscoveryService;