-- ===========================================================================================================
-- AUTHLY DATABASE SCHEMA - DOMAIN ANNOTATED
-- ===========================================================================================================
-- Purpose: Production PostgreSQL schema for Authly OAuth 2.1 + OIDC 1.0 Authorization Server
-- Version: Simplified (no ALTER statements, flattened structure)
-- Domains: CORE (authentication), OAUTH (OAuth 2.1), OIDC (OpenID Connect 1.0), GDPR (compliance)
-- ===========================================================================================================

-- ===========================================================================================================
-- ENVIRONMENT DETECTION AND USER CREATION
-- ===========================================================================================================
-- This script works in both production (Docker Compose) and test (testcontainer) environments
-- Production: Creates 'authly' user with POSTGRES_PASSWORD, grants on 'authly' database
-- Test: Uses existing 'test' user, works with 'authly_test' database

-- Check if we're in a testcontainer environment (test user exists, authly_test database)
DO
$env_setup$
DECLARE
    is_test_env BOOLEAN := FALSE;
    current_db TEXT;
    postgres_pwd TEXT;
BEGIN
    -- Get current database name
    SELECT current_database() INTO current_db;
    
    -- Check if we're in test environment (authly_test database exists)
    IF current_db = 'authly_test' THEN
        is_test_env := TRUE;
        RAISE NOTICE 'Detected test environment (database: %)', current_db;
    ELSE
        is_test_env := FALSE;
        RAISE NOTICE 'Detected production environment (database: %)', current_db;
    END IF;
    
    -- Only create authly user in production environment
    IF NOT is_test_env THEN
        -- Check if authly user already exists
        IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'authly') THEN
            -- Try to get POSTGRES_PASSWORD, fallback to default if not available
            BEGIN
                SELECT current_setting('POSTGRES_PASSWORD') INTO postgres_pwd;
            EXCEPTION
                WHEN undefined_object THEN
                    postgres_pwd := 'authly_default_password';
                    RAISE NOTICE 'POSTGRES_PASSWORD not found, using default password';
            END;
            
            -- Create authly user
            EXECUTE format('CREATE ROLE authly WITH LOGIN PASSWORD %L', postgres_pwd);
            RAISE NOTICE 'Created authly user for production environment';
            
            -- Grant connect permission on current database
            EXECUTE format('GRANT CONNECT ON DATABASE %I TO authly', current_db);
            GRANT USAGE ON SCHEMA public TO authly;
            GRANT CREATE ON SCHEMA public TO authly;
            GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO authly;
            GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO authly;
            GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO authly;
            
            -- Grant permissions on future objects
            ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO authly;
            ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO authly;
            ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON FUNCTIONS TO authly;
            
            RAISE NOTICE 'Granted permissions to authly user';
        ELSE
            RAISE NOTICE 'authly user already exists, skipping creation';
        END IF;
    ELSE
        RAISE NOTICE 'Test environment detected, using existing test user';
    END IF;
END
$env_setup$;

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ===========================================================================================================
-- CORE AUTHENTICATION DOMAIN - User Table
-- ===========================================================================================================
-- Purpose: Core user authentication and basic profile management
-- Domain: CORE + OIDC (some fields used for OIDC claims)
-- Service Split: Will belong to Identity Service in future architecture

CREATE TABLE IF NOT EXISTS users (
    -- CORE: Primary user identity
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),                    -- CORE: Internal user identifier
    username VARCHAR(50) UNIQUE NOT NULL,                             -- CORE: Login username
    email VARCHAR(255) UNIQUE NOT NULL,                               -- CORE + OIDC: Email address (used in OIDC email claim)
    password_hash VARCHAR(255) NOT NULL,                              -- CORE: Hashed password (bcrypt/argon2)
    
    -- CORE: Account management
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,    -- CORE: Account creation timestamp
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,    -- CORE: Last profile update
    last_login TIMESTAMP WITH TIME ZONE,                              -- CORE: Last successful login
    is_active BOOLEAN DEFAULT true,                                   -- CORE: Account active status
    is_verified BOOLEAN DEFAULT false,                                -- CORE: Email verification status
    is_admin BOOLEAN DEFAULT false,                                   -- CORE: Administrative privileges
    requires_password_change BOOLEAN DEFAULT false,                   -- CORE: Security flag for mandatory password change
    
    -- OIDC: Standard Claims - Profile scope (OpenID Connect Core 1.0 Section 5.1)
    given_name VARCHAR(255),                                          -- OIDC: Given name (first name) claim
    family_name VARCHAR(255),                                         -- OIDC: Family name (last name) claim  
    middle_name VARCHAR(255),                                         -- OIDC: Middle name claim
    nickname VARCHAR(255),                                            -- OIDC: Casual name claim
    preferred_username VARCHAR(255),                                  -- OIDC: Preferred username for display
    profile TEXT,                                                     -- OIDC: Profile page URL claim
    picture TEXT,                                                     -- OIDC: Profile picture URL claim
    website TEXT,                                                     -- OIDC: Personal website URL claim
    gender VARCHAR(50),                                               -- OIDC: Gender claim
    birthdate DATE,                                                   -- OIDC: Birthdate claim (YYYY-MM-DD format)
    zoneinfo VARCHAR(100),                                            -- OIDC: Time zone identifier claim
    locale VARCHAR(10),                                               -- OIDC: Preferred locale claim (e.g., en-US)

    -- OIDC: Standard Claims - Phone scope (OpenID Connect Core 1.0 Section 5.1.2)
    phone_number VARCHAR(50),                                         -- OIDC: Phone number claim
    phone_number_verified BOOLEAN,                                    -- OIDC: Phone number verification status

    -- OIDC: Standard Claims - Address scope (OpenID Connect Core 1.0 Section 5.1.1)
    address JSONB                                                     -- OIDC: Structured address claim
);

-- CORE: User lookup indexes
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);     -- CORE: Username lookup
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);           -- CORE: Email lookup
CREATE INDEX IF NOT EXISTS idx_users_requires_password_change ON users(requires_password_change) WHERE requires_password_change = TRUE; -- CORE: Password change required filter

-- OIDC: User OIDC claim indexes for performance optimization
CREATE INDEX IF NOT EXISTS idx_users_given_name ON users(given_name) WHERE given_name IS NOT NULL;  -- OIDC: Profile lookup optimization
CREATE INDEX IF NOT EXISTS idx_users_family_name ON users(family_name) WHERE family_name IS NOT NULL; -- OIDC: Profile lookup optimization
CREATE INDEX IF NOT EXISTS idx_users_preferred_username ON users(preferred_username) WHERE preferred_username IS NOT NULL; -- OIDC: Preferred username lookup
CREATE INDEX IF NOT EXISTS idx_users_phone_verified ON users(phone_number_verified) WHERE phone_number_verified IS NOT NULL; -- OIDC: Phone verification filtering
CREATE INDEX IF NOT EXISTS idx_users_locale ON users(locale) WHERE locale IS NOT NULL; -- OIDC: Locale-based filtering
CREATE INDEX IF NOT EXISTS idx_users_zoneinfo ON users(zoneinfo) WHERE zoneinfo IS NOT NULL; -- OIDC: Timezone-based filtering
CREATE INDEX IF NOT EXISTS idx_users_address_gin ON users USING GIN (address) WHERE address IS NOT NULL; -- OIDC: Address search optimization

-- CORE + ADMIN: Admin user management performance indexes (Increment 5.1 - Query Optimization)
-- Purpose: Optimize admin user listing, filtering, and session management queries
CREATE INDEX IF NOT EXISTS idx_users_admin_composite ON users(created_at DESC, is_active, is_admin, is_verified); -- ADMIN: Composite index for admin listing with sort and filters
CREATE INDEX IF NOT EXISTS idx_users_admin_text_search ON users USING gin(to_tsvector('english', COALESCE(username, '') || ' ' || COALESCE(email, '') || ' ' || COALESCE(given_name, '') || ' ' || COALESCE(family_name, ''))); -- ADMIN: Full-text search optimization
CREATE INDEX IF NOT EXISTS idx_users_admin_dates ON users(created_at, last_login); -- ADMIN: Date range filtering optimization

-- ===========================================================================================================
-- OAUTH 2.1 DOMAIN - OAuth Clients Table
-- ===========================================================================================================
-- Purpose: OAuth 2.1 client application registration and management
-- Domain: OAUTH + OIDC (OIDC extends OAuth client metadata)
-- Service Split: Will belong to Authorization Service in future architecture

CREATE TABLE IF NOT EXISTS oauth_clients (
    -- OAUTH: Core client identity
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),                    -- OAUTH: Internal client identifier
    client_id VARCHAR(255) UNIQUE NOT NULL,                           -- OAUTH: Public client identifier
    client_secret_hash VARCHAR(255),                                  -- OAUTH: Hashed client secret (NULL for public clients)
    client_name VARCHAR(255) NOT NULL,                                -- OAUTH: Human-readable client name
    client_type VARCHAR(20) NOT NULL CHECK (client_type IN ('confidential', 'public')), -- OAUTH: Client type
    
    -- OAUTH: Authorization flow configuration
    redirect_uris TEXT[] NOT NULL,                                    -- OAUTH: Allowed redirect URIs
    grant_types TEXT[] NOT NULL DEFAULT ARRAY['authorization_code', 'refresh_token'], -- OAUTH: Supported grant types
    response_types TEXT[] NOT NULL DEFAULT ARRAY['code'],             -- OAUTH: Supported response types
    scope TEXT,                                                       -- OAUTH: Default scopes (space-separated)
    
    -- OAUTH: Account management
    is_active BOOLEAN DEFAULT true,                                   -- OAUTH: Client active status
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,    -- OAUTH: Client registration timestamp
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,    -- OAUTH: Last client update
    
    -- OAUTH 2.1: Security requirements
    require_pkce BOOLEAN DEFAULT true,                                -- OAUTH 2.1: PKCE requirement (mandatory)
    token_endpoint_auth_method VARCHAR(50) DEFAULT 'client_secret_basic', -- OAUTH: Token endpoint authentication
    
    -- OAUTH: Client metadata
    client_uri TEXT,                                                  -- OAUTH: Client homepage URL
    logo_uri TEXT,                                                    -- OAUTH: Client logo URL
    tos_uri TEXT,                                                     -- OAUTH: Terms of service URL
    policy_uri TEXT,                                                  -- OAUTH: Privacy policy URL
    jwks_uri TEXT,                                                    -- OAUTH: JSON Web Key Set URI
    software_id VARCHAR(255),                                         -- OAUTH: Software identifier
    software_version VARCHAR(50),                                     -- OAUTH: Software version
    
    -- OIDC: OpenID Connect client configuration
    id_token_signed_response_alg VARCHAR(10) DEFAULT 'RS256' CHECK (id_token_signed_response_alg IN ('RS256', 'HS256', 'ES256')), -- OIDC: ID token signing algorithm
    subject_type VARCHAR(10) DEFAULT 'public' CHECK (subject_type IN ('public', 'pairwise')), -- OIDC: Subject identifier type
    sector_identifier_uri TEXT,                                       -- OIDC: Sector identifier URI (pairwise subjects)
    require_auth_time BOOLEAN DEFAULT false,                          -- OIDC: Require auth_time claim
    default_max_age INTEGER CHECK (default_max_age >= 0),             -- OIDC: Default maximum authentication age
    initiate_login_uri TEXT,                                          -- OIDC: Client-initiated login URI
    request_uris TEXT[] DEFAULT ARRAY[]::TEXT[],                      -- OIDC: Request object URIs
    application_type VARCHAR(10) DEFAULT 'web' CHECK (application_type IN ('web', 'native')), -- OIDC: Application type
    contacts TEXT[] DEFAULT ARRAY[]::TEXT[],                          -- OIDC: Client contact information
    
    -- OIDC: Localized client metadata
    client_name_localized JSONB,                                      -- OIDC: Localized client names
    logo_uri_localized JSONB,                                         -- OIDC: Localized logo URIs
    client_uri_localized JSONB,                                       -- OIDC: Localized client URIs
    policy_uri_localized JSONB,                                       -- OIDC: Localized privacy policy URIs
    tos_uri_localized JSONB                                           -- OIDC: Localized terms of service URIs
);

-- OAUTH: Client lookup indexes
CREATE INDEX IF NOT EXISTS idx_oauth_clients_client_id ON oauth_clients(client_id); -- OAUTH: Client ID lookup
CREATE INDEX IF NOT EXISTS idx_oauth_clients_active ON oauth_clients(is_active);    -- OAUTH: Active client filtering

-- ===========================================================================================================
-- OAUTH 2.1 DOMAIN - Token Table
-- ===========================================================================================================
-- Purpose: OAuth 2.1 access and refresh token management
-- Domain: OAUTH (core token functionality)
-- Service Split: Will belong to Authorization Service in future architecture

CREATE TABLE IF NOT EXISTS tokens (
    -- OAUTH: Token identity
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),                    -- OAUTH: Internal token identifier
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,    -- OAUTH: Token owner (user)
    client_id UUID REFERENCES oauth_clients(id) ON DELETE SET NULL,  -- OAUTH: Issuing client (NULL for non-OAuth tokens)
    token_jti VARCHAR(64) NOT NULL UNIQUE,                           -- OAUTH: JWT ID claim (unique identifier)
    token_type VARCHAR(10) NOT NULL CHECK (token_type IN ('access', 'refresh')), -- OAUTH: Token type
    token_value TEXT NOT NULL,                                       -- OAUTH: Token value (JWT or opaque)
    scope TEXT,                                                      -- OAUTH: Granted scopes (space-separated)
    
    -- OAUTH: Token lifecycle management
    invalidated BOOLEAN NOT NULL DEFAULT false,                       -- OAUTH: Token invalidation status
    invalidated_at TIMESTAMP WITH TIME ZONE,                         -- OAUTH: Token invalidation timestamp
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,                    -- OAUTH: Token expiration timestamp
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP, -- OAUTH: Token creation timestamp
    
    -- OAUTH: Optional tracking fields (GDPR considerations)
    created_by_ip VARCHAR(45),                                       -- OAUTH: Client IP address (optional, GDPR: personal data)
    user_agent TEXT                                                  -- OAUTH: Client user agent (optional, GDPR: personal data)
);

-- OAUTH: Token lookup indexes
CREATE INDEX IF NOT EXISTS idx_tokens_user_id ON tokens(user_id);     -- OAUTH: User token lookup
CREATE INDEX IF NOT EXISTS idx_tokens_jti ON tokens(token_jti);       -- OAUTH: JTI lookup (token identification)
CREATE INDEX IF NOT EXISTS idx_tokens_expires_at ON tokens(expires_at); -- OAUTH: Expiration-based cleanup
CREATE INDEX IF NOT EXISTS idx_tokens_client_id ON tokens(client_id); -- OAUTH: Client token lookup
CREATE INDEX IF NOT EXISTS idx_tokens_scope ON tokens(scope);         -- OAUTH: Scope-based filtering

-- OAUTH + ADMIN: Token session management performance indexes (Increment 5.1 - Query Optimization)
-- Purpose: Optimize admin session counting, listing, and revocation queries
CREATE INDEX IF NOT EXISTS idx_tokens_session_count ON tokens(user_id, token_type, invalidated, expires_at) WHERE token_type = 'access'; -- ADMIN: Active session counting optimization
CREATE INDEX IF NOT EXISTS idx_tokens_session_listing ON tokens(user_id, created_at DESC, invalidated, expires_at); -- ADMIN: Session listing optimization
CREATE INDEX IF NOT EXISTS idx_tokens_active_sessions ON tokens(user_id, created_at DESC) WHERE token_type = 'access' AND invalidated = false; -- ADMIN: Active session partial index (without expires_at check for immutability)

-- ===========================================================================================================
-- OAUTH 2.1 DOMAIN - OAuth Scopes Table
-- ===========================================================================================================
-- Purpose: OAuth 2.1 scope definition and management
-- Domain: OAUTH + OIDC (OIDC defines additional standard scopes)
-- Service Split: Will belong to Authorization Service in future architecture

CREATE TABLE IF NOT EXISTS oauth_scopes (
    -- OAUTH: Scope identity
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),                    -- OAUTH: Internal scope identifier
    scope_name VARCHAR(255) UNIQUE NOT NULL,                         -- OAUTH: Scope name (e.g., 'read', 'write')
    description TEXT,                                                 -- OAUTH: Human-readable scope description
    is_default BOOLEAN DEFAULT false,                                -- OAUTH: Default scope assignment
    is_active BOOLEAN DEFAULT true,                                  -- OAUTH: Scope active status
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,   -- OAUTH: Scope creation timestamp
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP    -- OAUTH: Scope update timestamp
);

-- OAUTH: Scope lookup indexes
CREATE INDEX IF NOT EXISTS idx_oauth_scopes_name ON oauth_scopes(scope_name);    -- OAUTH: Scope name lookup
CREATE INDEX IF NOT EXISTS idx_oauth_scopes_active ON oauth_scopes(is_active);   -- OAUTH: Active scope filtering
CREATE INDEX IF NOT EXISTS idx_oauth_scopes_default ON oauth_scopes(is_default); -- OAUTH: Default scope selection

-- ===========================================================================================================
-- OAUTH 2.1 DOMAIN - Client-Scope Associations
-- ===========================================================================================================
-- Purpose: OAuth 2.1 client-scope relationship management
-- Domain: OAUTH (scope authorization)
-- Service Split: Will belong to Authorization Service in future architecture

CREATE TABLE IF NOT EXISTS oauth_client_scopes (
    -- OAUTH: Association identity
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),                    -- OAUTH: Internal association identifier
    client_id UUID NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE, -- OAUTH: Client reference
    scope_id UUID NOT NULL REFERENCES oauth_scopes(id) ON DELETE CASCADE,   -- OAUTH: Scope reference
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,   -- OAUTH: Association creation timestamp
    UNIQUE(client_id, scope_id)                                      -- OAUTH: Prevent duplicate associations
);

-- OAUTH: Client-scope lookup indexes
CREATE INDEX IF NOT EXISTS idx_oauth_client_scopes_client ON oauth_client_scopes(client_id); -- OAUTH: Client scope lookup
CREATE INDEX IF NOT EXISTS idx_oauth_client_scopes_scope ON oauth_client_scopes(scope_id);   -- OAUTH: Scope client lookup

-- ===========================================================================================================
-- OAUTH 2.1 DOMAIN - Authorization Codes Table
-- ===========================================================================================================
-- Purpose: OAuth 2.1 authorization code flow with OIDC parameter support
-- Domain: OAUTH + OIDC (OIDC extends authorization parameters)
-- Service Split: Will belong to Authorization Service in future architecture

CREATE TABLE IF NOT EXISTS oauth_authorization_codes (
    -- OAUTH: Authorization code identity
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),                    -- OAUTH: Internal code identifier
    code VARCHAR(255) UNIQUE NOT NULL,                               -- OAUTH: Authorization code value
    client_id UUID NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE, -- OAUTH: Requesting client
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,    -- OAUTH: Authorizing user
    redirect_uri TEXT NOT NULL,                                      -- OAUTH: Redirect URI (must match client)
    scope TEXT,                                                      -- OAUTH: Granted scopes (space-separated)
    
    -- OAUTH: Code lifecycle management
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,                    -- OAUTH: Code expiration (short-lived)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,   -- OAUTH: Code creation timestamp
    used_at TIMESTAMP WITH TIME ZONE,                                -- OAUTH: Code exchange timestamp
    is_used BOOLEAN DEFAULT false,                                   -- OAUTH: Code usage status
    
    -- OAUTH 2.1: PKCE (Proof Key for Code Exchange) - MANDATORY
    code_challenge VARCHAR(255) NOT NULL,                            -- OAUTH 2.1: PKCE code challenge
    code_challenge_method VARCHAR(10) NOT NULL DEFAULT 'S256' CHECK (code_challenge_method IN ('S256')), -- OAUTH 2.1: PKCE method (S256 only)
    
    -- OIDC: OpenID Connect authorization parameters
    nonce VARCHAR(255),                                              -- OIDC: Nonce for ID token binding
    state VARCHAR(255),                                              -- OIDC: State parameter (CSRF protection)
    response_mode VARCHAR(20) CHECK (response_mode IN ('query', 'fragment', 'form_post')), -- OIDC: Response mode
    display VARCHAR(20) CHECK (display IN ('page', 'popup', 'touch', 'wap')), -- OIDC: Display preference
    prompt VARCHAR(20) CHECK (prompt IN ('none', 'login', 'consent', 'select_account')), -- OIDC: Prompt behavior
    max_age INTEGER CHECK (max_age >= 0),                            -- OIDC: Maximum authentication age
    ui_locales VARCHAR(255),                                         -- OIDC: UI locale preferences
    id_token_hint TEXT,                                              -- OIDC: ID token hint
    login_hint VARCHAR(255),                                         -- OIDC: Login hint
    acr_values VARCHAR(255)                                          -- OIDC: Authentication Context Class Reference
);

-- OAUTH: Authorization code lookup indexes
CREATE INDEX IF NOT EXISTS idx_oauth_authz_codes_code ON oauth_authorization_codes(code);       -- OAUTH: Code lookup
CREATE INDEX IF NOT EXISTS idx_oauth_authz_codes_client ON oauth_authorization_codes(client_id); -- OAUTH: Client code lookup
CREATE INDEX IF NOT EXISTS idx_oauth_authz_codes_user ON oauth_authorization_codes(user_id);     -- OAUTH: User code lookup
CREATE INDEX IF NOT EXISTS idx_oauth_authz_codes_expires ON oauth_authorization_codes(expires_at); -- OAUTH: Expiration cleanup
CREATE INDEX IF NOT EXISTS idx_oauth_authz_codes_used ON oauth_authorization_codes(is_used);     -- OAUTH: Usage status filtering

-- ===========================================================================================================
-- OAUTH 2.1 DOMAIN - Token-Scope Associations
-- ===========================================================================================================
-- Purpose: OAuth 2.1 token-scope relationship management
-- Domain: OAUTH (token scope tracking)
-- Service Split: Will belong to Authorization Service in future architecture

CREATE TABLE IF NOT EXISTS oauth_token_scopes (
    -- OAUTH: Association identity
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),                    -- OAUTH: Internal association identifier
    token_id UUID NOT NULL REFERENCES tokens(id) ON DELETE CASCADE,  -- OAUTH: Token reference
    scope_id UUID NOT NULL REFERENCES oauth_scopes(id) ON DELETE CASCADE, -- OAUTH: Scope reference
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,   -- OAUTH: Association creation timestamp
    UNIQUE(token_id, scope_id)                                       -- OAUTH: Prevent duplicate associations
);

-- OAUTH: Token-scope lookup indexes
CREATE INDEX IF NOT EXISTS idx_oauth_token_scopes_token ON oauth_token_scopes(token_id); -- OAUTH: Token scope lookup
CREATE INDEX IF NOT EXISTS idx_oauth_token_scopes_scope ON oauth_token_scopes(scope_id); -- OAUTH: Scope token lookup

-- ===========================================================================================================
-- OIDC DOMAIN - JWKS (JSON Web Key Set) Table
-- ===========================================================================================================
-- Purpose: OpenID Connect cryptographic key management
-- Domain: OIDC (ID token signing and verification)
-- Service Split: Will belong to Identity Service in future architecture

CREATE TABLE IF NOT EXISTS oidc_jwks_keys (
    -- OIDC: Key identity
    kid VARCHAR(255) PRIMARY KEY,                                     -- OIDC: Key ID (unique identifier)
    key_data JSONB NOT NULL,                                         -- OIDC: JWK data in JSON format
    key_type VARCHAR(10) NOT NULL CHECK (key_type IN ('RSA', 'EC', 'oct')), -- OIDC: Key type
    algorithm VARCHAR(10) NOT NULL CHECK (algorithm IN ('RS256', 'ES256', 'HS256')), -- OIDC: Signing algorithm
    key_use VARCHAR(10) NOT NULL DEFAULT 'sig' CHECK (key_use IN ('sig', 'enc')), -- OIDC: Key usage
    
    -- OIDC: Key lifecycle management
    is_active BOOLEAN DEFAULT true,                                   -- OIDC: Key active status
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,   -- OIDC: Key creation timestamp
    expires_at TIMESTAMP WITH TIME ZONE,                             -- OIDC: Key expiration (for rotation)
    
    -- OIDC: Key metadata
    key_size INTEGER,                                                 -- OIDC: Key size in bits
    curve VARCHAR(20)                                                -- OIDC: Elliptic curve name (for EC keys)
);

-- OIDC: JWKS lookup indexes
CREATE INDEX IF NOT EXISTS idx_oidc_jwks_kid ON oidc_jwks_keys(kid);           -- OIDC: Key ID lookup
CREATE INDEX IF NOT EXISTS idx_oidc_jwks_active ON oidc_jwks_keys(is_active);  -- OIDC: Active key filtering
CREATE INDEX IF NOT EXISTS idx_oidc_jwks_expires ON oidc_jwks_keys(expires_at); -- OIDC: Key expiration management
CREATE INDEX IF NOT EXISTS idx_oidc_jwks_algorithm ON oidc_jwks_keys(algorithm); -- OIDC: Algorithm-based selection

-- ===========================================================================================================
-- TRIGGER FUNCTIONS - Cross-Domain Utilities
-- ===========================================================================================================
-- Purpose: Automatic timestamp management for all domains
-- Domain: CORE (utility functions)
-- Service Split: Will be replicated across services

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- CORE: User timestamp management
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- OAUTH: Client timestamp management
CREATE TRIGGER update_oauth_clients_updated_at
    BEFORE UPDATE ON oauth_clients
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- OAUTH: Scope timestamp management
CREATE TRIGGER update_oauth_scopes_updated_at
    BEFORE UPDATE ON oauth_scopes
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ===========================================================================================================
-- DEFAULT DATA - Domain-Specific Seed Data
-- ===========================================================================================================
-- Purpose: Initialize OAuth 2.1 and OIDC standard scopes
-- Domain: OAUTH + OIDC (standard scope definitions)

INSERT INTO oauth_scopes (scope_name, description, is_default, is_active) VALUES
    -- OAUTH: Standard OAuth 2.1 scopes
    ('read', 'Read access to user data', false, true),               -- OAUTH: Read permission
    ('write', 'Write access to user data', false, true),             -- OAUTH: Write permission
    ('profile', 'Access to basic profile information', true, true),   -- OAUTH + OIDC: Profile access
    ('email', 'Access to email address', false, true),               -- OAUTH + OIDC: Email access
    ('admin', 'Administrative access', false, true),                 -- OAUTH: Admin permission
    
    -- OIDC: OpenID Connect standard scopes
    ('openid', 'OpenID Connect authentication scope', false, true),  -- OIDC: Required for OIDC flows
    ('address', 'Access to user physical mailing address', false, true), -- OIDC: Address claims
    ('phone', 'Access to user phone number and verification status', false, true) -- OIDC: Phone claims
ON CONFLICT (scope_name) DO NOTHING;

-- ===========================================================================================================
-- FUTURE GDPR COMPLIANCE TABLES (Not Yet Implemented)
-- ===========================================================================================================
-- Purpose: GDPR Article compliance tracking
-- Domain: GDPR (data protection and privacy)
-- Service Split: Will belong to dedicated Compliance Service

-- GDPR: User consent tracking (Article 7)
-- CREATE TABLE IF NOT EXISTS gdpr_user_consents (
--     id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--     user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
--     consent_type VARCHAR(50) NOT NULL,                           -- GDPR: Type of consent
--     consent_version VARCHAR(20) NOT NULL,                        -- GDPR: Consent version
--     granted_at TIMESTAMP WITH TIME ZONE NOT NULL,                -- GDPR: Consent timestamp
--     withdrawn_at TIMESTAMP WITH TIME ZONE,                       -- GDPR: Withdrawal timestamp
--     is_active BOOLEAN DEFAULT true,                              -- GDPR: Current consent status
--     consent_data JSONB,                                          -- GDPR: Detailed consent information
--     ip_address VARCHAR(45),                                      -- GDPR: Consent origin IP
--     user_agent TEXT                                              -- GDPR: Consent origin user agent
-- );

-- GDPR: Audit logging (Article 30)
-- CREATE TABLE IF NOT EXISTS gdpr_audit_logs (
--     id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--     user_id UUID REFERENCES users(id) ON DELETE SET NULL,
--     action VARCHAR(100) NOT NULL,                                -- GDPR: Action performed
--     resource_type VARCHAR(50) NOT NULL,                          -- GDPR: Resource type affected
--     resource_id VARCHAR(255),                                    -- GDPR: Resource identifier
--     timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP, -- GDPR: Action timestamp
--     ip_address VARCHAR(45),                                      -- GDPR: Source IP address
--     user_agent TEXT,                                             -- GDPR: Source user agent
--     details JSONB                                                -- GDPR: Additional audit details
-- );

-- GDPR: Data retention policies (Article 5)
-- CREATE TABLE IF NOT EXISTS gdpr_retention_policies (
--     id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--     data_type VARCHAR(50) NOT NULL,                              -- GDPR: Type of data
--     retention_period_days INTEGER NOT NULL,                      -- GDPR: Retention period
--     description TEXT,                                            -- GDPR: Policy description
--     is_active BOOLEAN DEFAULT true,                              -- GDPR: Policy active status
--     created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP -- GDPR: Policy creation
-- );

-- ===========================================================================================================
-- SCHEMA SUMMARY - Service Split Preparation
-- ===========================================================================================================
-- Future Service Architecture Mapping:
--
-- IDENTITY SERVICE (Core Authentication + OIDC):
-- - users table (with OIDC claims)
-- - oidc_jwks_keys table
-- - OIDC-specific endpoints and ID token generation
--
-- AUTHORIZATION SERVICE (OAuth 2.1):
-- - oauth_clients table
-- - oauth_scopes table
-- - oauth_client_scopes table
-- - oauth_authorization_codes table
-- - tokens table
-- - oauth_token_scopes table
--
-- COMPLIANCE SERVICE (GDPR):
-- - gdpr_user_consents table (future)
-- - gdpr_audit_logs table (future)
-- - gdpr_retention_policies table (future)
--
-- SHARED UTILITIES:
-- - update_updated_at_column() function
-- - Common trigger patterns
-- - UUID generation patterns
--
-- ===========================================================================================================
