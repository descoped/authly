 -- Enable required extensions
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ---------------------------------------------------------------------------------------------------------
-- BEGIN User Table
-- ---------------------------------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT true,
    is_verified BOOLEAN DEFAULT false,
    is_admin BOOLEAN DEFAULT false
);

-- Rest of the code remains unchanged
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ---------------------------------------------------------------------------------------------------------
-- END User Table
-- ---------------------------------------------------------------------------------------------------------

-- ---------------------------------------------------------------------------------------------------------
-- BEGIN Token Table
-- ---------------------------------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_jti VARCHAR(64) NOT NULL UNIQUE,
    token_type VARCHAR(10) NOT NULL CHECK (token_type IN ('access', 'refresh')),
    token_value TEXT NOT NULL,  -- Added this column
    invalidated BOOLEAN NOT NULL DEFAULT false,
    invalidated_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by_ip VARCHAR(45),  -- Optional fields
    user_agent TEXT
);

CREATE INDEX IF NOT EXISTS idx_tokens_user_id ON tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_tokens_jti ON tokens(token_jti);
CREATE INDEX IF NOT EXISTS idx_tokens_expires_at ON tokens(expires_at);

-- ---------------------------------------------------------------------------------------------------------
-- END Token Table
-- ---------------------------------------------------------------------------------------------------------

-- ---------------------------------------------------------------------------------------------------------
-- BEGIN OAuth 2.1 Schema
-- ---------------------------------------------------------------------------------------------------------

-- OAuth clients table - stores registered client applications
CREATE TABLE IF NOT EXISTS oauth_clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id VARCHAR(255) UNIQUE NOT NULL,
    client_secret_hash VARCHAR(255), -- NULL for public clients (PKCE only)
    client_name VARCHAR(255) NOT NULL,
    client_type VARCHAR(20) NOT NULL CHECK (client_type IN ('confidential', 'public')),
    redirect_uris TEXT[] NOT NULL, -- Array of allowed redirect URIs
    grant_types TEXT[] NOT NULL DEFAULT ARRAY['authorization_code', 'refresh_token'], -- Supported grant types
    response_types TEXT[] NOT NULL DEFAULT ARRAY['code'], -- Supported response types
    scope TEXT, -- Default scopes for this client (space-separated)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT true,
    -- OAuth 2.1 specific fields
    require_pkce BOOLEAN DEFAULT true, -- OAuth 2.1 recommends PKCE for all clients
    token_endpoint_auth_method VARCHAR(50) DEFAULT 'client_secret_basic', -- or 'none' for public clients
    -- Additional metadata
    client_uri TEXT, -- Homepage of the client
    logo_uri TEXT, -- Logo for consent screen
    tos_uri TEXT, -- Terms of service
    policy_uri TEXT, -- Privacy policy
    jwks_uri TEXT, -- JSON Web Key Set URI for JWT validation
    software_id VARCHAR(255), -- Software identifier
    software_version VARCHAR(50) -- Software version
);

-- OAuth scopes table - defines available permission scopes
CREATE TABLE IF NOT EXISTS oauth_scopes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_name VARCHAR(255) UNIQUE NOT NULL, -- e.g., 'read', 'write', 'profile'
    description TEXT, -- Human-readable description
    is_default BOOLEAN DEFAULT false, -- Whether this scope is granted by default
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT true
);

-- Client-scope associations - which scopes each client can request
CREATE TABLE IF NOT EXISTS oauth_client_scopes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id UUID NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    scope_id UUID NOT NULL REFERENCES oauth_scopes(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(client_id, scope_id)
);

-- Authorization codes table - temporary codes for OAuth 2.1 authorization flow with OpenID Connect support
CREATE TABLE IF NOT EXISTS oauth_authorization_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code VARCHAR(255) UNIQUE NOT NULL, -- The authorization code
    client_id UUID NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL, -- Must match one from client's redirect_uris
    scope TEXT, -- Granted scopes (space-separated)
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL, -- Codes expire quickly (10 minutes max)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    used_at TIMESTAMP WITH TIME ZONE, -- When the code was exchanged for tokens
    is_used BOOLEAN DEFAULT false,
    -- PKCE fields (OAuth 2.1 requirement)
    code_challenge VARCHAR(255) NOT NULL, -- Base64url-encoded SHA256 hash
    code_challenge_method VARCHAR(10) NOT NULL DEFAULT 'S256' CHECK (code_challenge_method IN ('S256')), -- OAuth 2.1 only allows S256
    -- OpenID Connect parameters
    nonce VARCHAR(255), -- OpenID Connect nonce for ID token binding
    state VARCHAR(255), -- CSRF protection state parameter
    response_mode VARCHAR(20) CHECK (response_mode IN ('query', 'fragment', 'form_post')), -- Response mode
    display VARCHAR(20) CHECK (display IN ('page', 'popup', 'touch', 'wap')), -- Display preference
    prompt VARCHAR(20) CHECK (prompt IN ('none', 'login', 'consent', 'select_account')), -- Prompt parameter
    max_age INTEGER CHECK (max_age >= 0), -- Maximum authentication age in seconds
    ui_locales VARCHAR(255), -- UI locales preference (space-separated)
    id_token_hint TEXT, -- ID token hint for logout or re-authentication
    login_hint VARCHAR(255), -- Login hint to identify the user
    acr_values VARCHAR(255) -- Authentication Context Class Reference values (space-separated)
);

-- Token scopes table - tracks which scopes are associated with each token
CREATE TABLE IF NOT EXISTS oauth_token_scopes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_id UUID NOT NULL REFERENCES tokens(id) ON DELETE CASCADE,
    scope_id UUID NOT NULL REFERENCES oauth_scopes(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(token_id, scope_id)
);

-- OAuth refresh token tracking - enhanced token management for OAuth flows
-- Note: We extend the existing tokens table rather than create a new one
-- Add OAuth-specific columns to tokens table
DO $$
BEGIN
    -- Add client_id column to tokens table for OAuth flows
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'tokens' AND column_name = 'client_id'
    ) THEN
        ALTER TABLE tokens ADD COLUMN client_id UUID REFERENCES oauth_clients(id) ON DELETE SET NULL;
    END IF;
    
    -- Add scope column to tokens table
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'tokens' AND column_name = 'scope'
    ) THEN
        ALTER TABLE tokens ADD COLUMN scope TEXT; -- Space-separated list of granted scopes
    END IF;
END $$;

-- ---------------------------------------------------------------------------------------------------------
-- BEGIN OAuth 2.1 Indexes
-- ---------------------------------------------------------------------------------------------------------

-- OAuth clients indexes
CREATE INDEX IF NOT EXISTS idx_oauth_clients_client_id ON oauth_clients(client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_clients_active ON oauth_clients(is_active);

-- OAuth scopes indexes  
CREATE INDEX IF NOT EXISTS idx_oauth_scopes_name ON oauth_scopes(scope_name);
CREATE INDEX IF NOT EXISTS idx_oauth_scopes_active ON oauth_scopes(is_active);
CREATE INDEX IF NOT EXISTS idx_oauth_scopes_default ON oauth_scopes(is_default);

-- Client-scope indexes
CREATE INDEX IF NOT EXISTS idx_oauth_client_scopes_client ON oauth_client_scopes(client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_client_scopes_scope ON oauth_client_scopes(scope_id);

-- Authorization codes indexes
CREATE INDEX IF NOT EXISTS idx_oauth_authz_codes_code ON oauth_authorization_codes(code);
CREATE INDEX IF NOT EXISTS idx_oauth_authz_codes_client ON oauth_authorization_codes(client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_authz_codes_user ON oauth_authorization_codes(user_id);
CREATE INDEX IF NOT EXISTS idx_oauth_authz_codes_expires ON oauth_authorization_codes(expires_at);
CREATE INDEX IF NOT EXISTS idx_oauth_authz_codes_used ON oauth_authorization_codes(is_used);

-- Token scopes indexes
CREATE INDEX IF NOT EXISTS idx_oauth_token_scopes_token ON oauth_token_scopes(token_id);
CREATE INDEX IF NOT EXISTS idx_oauth_token_scopes_scope ON oauth_token_scopes(scope_id);

-- Enhanced token indexes for OAuth
CREATE INDEX IF NOT EXISTS idx_tokens_client_id ON tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_tokens_scope ON tokens(scope);

-- ---------------------------------------------------------------------------------------------------------
-- BEGIN OAuth 2.1 Triggers
-- ---------------------------------------------------------------------------------------------------------

-- Update triggers for timestamp columns
CREATE TRIGGER update_oauth_clients_updated_at
    BEFORE UPDATE ON oauth_clients
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_oauth_scopes_updated_at
    BEFORE UPDATE ON oauth_scopes
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ---------------------------------------------------------------------------------------------------------
-- BEGIN OpenID Connect Schema Migration
-- ---------------------------------------------------------------------------------------------------------

-- Add OpenID Connect columns to oauth_authorization_codes table if they don't exist
DO $$
BEGIN
    -- Add response_mode column
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'oauth_authorization_codes' AND column_name = 'response_mode'
    ) THEN
        ALTER TABLE oauth_authorization_codes ADD COLUMN response_mode VARCHAR(20) CHECK (response_mode IN ('query', 'fragment', 'form_post'));
    END IF;
    
    -- Add display column
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'oauth_authorization_codes' AND column_name = 'display'
    ) THEN
        ALTER TABLE oauth_authorization_codes ADD COLUMN display VARCHAR(20) CHECK (display IN ('page', 'popup', 'touch', 'wap'));
    END IF;
    
    -- Add prompt column
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'oauth_authorization_codes' AND column_name = 'prompt'
    ) THEN
        ALTER TABLE oauth_authorization_codes ADD COLUMN prompt VARCHAR(20) CHECK (prompt IN ('none', 'login', 'consent', 'select_account'));
    END IF;
    
    -- Add max_age column
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'oauth_authorization_codes' AND column_name = 'max_age'
    ) THEN
        ALTER TABLE oauth_authorization_codes ADD COLUMN max_age INTEGER CHECK (max_age >= 0);
    END IF;
    
    -- Add ui_locales column
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'oauth_authorization_codes' AND column_name = 'ui_locales'
    ) THEN
        ALTER TABLE oauth_authorization_codes ADD COLUMN ui_locales VARCHAR(255);
    END IF;
    
    -- Add id_token_hint column
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'oauth_authorization_codes' AND column_name = 'id_token_hint'
    ) THEN
        ALTER TABLE oauth_authorization_codes ADD COLUMN id_token_hint TEXT;
    END IF;
    
    -- Add login_hint column
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'oauth_authorization_codes' AND column_name = 'login_hint'
    ) THEN
        ALTER TABLE oauth_authorization_codes ADD COLUMN login_hint VARCHAR(255);
    END IF;
    
    -- Add acr_values column
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'oauth_authorization_codes' AND column_name = 'acr_values'
    ) THEN
        ALTER TABLE oauth_authorization_codes ADD COLUMN acr_values VARCHAR(255);
    END IF;
END $$;

-- ---------------------------------------------------------------------------------------------------------
-- END OpenID Connect Schema Migration
-- ---------------------------------------------------------------------------------------------------------

-- ---------------------------------------------------------------------------------------------------------
-- BEGIN OIDC Client Management Schema Migration
-- ---------------------------------------------------------------------------------------------------------

-- Add OpenID Connect client fields to oauth_clients table if they don't exist
DO $$
BEGIN
    -- Add id_token_signed_response_alg column
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'oauth_clients' AND column_name = 'id_token_signed_response_alg'
    ) THEN
        ALTER TABLE oauth_clients ADD COLUMN id_token_signed_response_alg VARCHAR(10) DEFAULT 'RS256' CHECK (id_token_signed_response_alg IN ('RS256', 'HS256', 'ES256'));
    END IF;
    
    -- Add subject_type column
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'oauth_clients' AND column_name = 'subject_type'
    ) THEN
        ALTER TABLE oauth_clients ADD COLUMN subject_type VARCHAR(10) DEFAULT 'public' CHECK (subject_type IN ('public', 'pairwise'));
    END IF;
    
    -- Add sector_identifier_uri column
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'oauth_clients' AND column_name = 'sector_identifier_uri'
    ) THEN
        ALTER TABLE oauth_clients ADD COLUMN sector_identifier_uri TEXT;
    END IF;
    
    -- Add require_auth_time column
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'oauth_clients' AND column_name = 'require_auth_time'
    ) THEN
        ALTER TABLE oauth_clients ADD COLUMN require_auth_time BOOLEAN DEFAULT false;
    END IF;
    
    -- Add default_max_age column
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'oauth_clients' AND column_name = 'default_max_age'
    ) THEN
        ALTER TABLE oauth_clients ADD COLUMN default_max_age INTEGER CHECK (default_max_age >= 0);
    END IF;
    
    -- Add initiate_login_uri column
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'oauth_clients' AND column_name = 'initiate_login_uri'
    ) THEN
        ALTER TABLE oauth_clients ADD COLUMN initiate_login_uri TEXT;
    END IF;
    
    -- Add request_uris column
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'oauth_clients' AND column_name = 'request_uris'
    ) THEN
        ALTER TABLE oauth_clients ADD COLUMN request_uris TEXT[] DEFAULT ARRAY[]::TEXT[];
    END IF;
    
    -- Add application_type column
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'oauth_clients' AND column_name = 'application_type'
    ) THEN
        ALTER TABLE oauth_clients ADD COLUMN application_type VARCHAR(10) DEFAULT 'web' CHECK (application_type IN ('web', 'native'));
    END IF;
    
    -- Add contacts column
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'oauth_clients' AND column_name = 'contacts'
    ) THEN
        ALTER TABLE oauth_clients ADD COLUMN contacts TEXT[] DEFAULT ARRAY[]::TEXT[];
    END IF;
    
    -- Add client_name_localized column
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'oauth_clients' AND column_name = 'client_name_localized'
    ) THEN
        ALTER TABLE oauth_clients ADD COLUMN client_name_localized JSONB;
    END IF;
    
    -- Add logo_uri_localized column
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'oauth_clients' AND column_name = 'logo_uri_localized'
    ) THEN
        ALTER TABLE oauth_clients ADD COLUMN logo_uri_localized JSONB;
    END IF;
    
    -- Add client_uri_localized column
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'oauth_clients' AND column_name = 'client_uri_localized'
    ) THEN
        ALTER TABLE oauth_clients ADD COLUMN client_uri_localized JSONB;
    END IF;
    
    -- Add policy_uri_localized column
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'oauth_clients' AND column_name = 'policy_uri_localized'
    ) THEN
        ALTER TABLE oauth_clients ADD COLUMN policy_uri_localized JSONB;
    END IF;
    
    -- Add tos_uri_localized column
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'oauth_clients' AND column_name = 'tos_uri_localized'
    ) THEN
        ALTER TABLE oauth_clients ADD COLUMN tos_uri_localized JSONB;
    END IF;
END $$;

-- ---------------------------------------------------------------------------------------------------------
-- END OIDC Client Management Schema Migration
-- ---------------------------------------------------------------------------------------------------------

-- ---------------------------------------------------------------------------------------------------------
-- BEGIN Default OAuth 2.1 Data
-- ---------------------------------------------------------------------------------------------------------

-- Insert default scopes including OpenID Connect scopes
INSERT INTO oauth_scopes (scope_name, description, is_default, is_active) VALUES
    ('read', 'Read access to user data', false, true),
    ('write', 'Write access to user data', false, true),
    ('profile', 'Access to basic profile information', true, true),
    ('email', 'Access to email address', false, true),
    ('admin', 'Administrative access', false, true),
    -- OpenID Connect scopes
    ('openid', 'OpenID Connect authentication scope (required for OIDC flows)', false, true),
    ('address', 'Access to user physical mailing address', false, true),
    ('phone', 'Access to user phone number and verification status', false, true)
ON CONFLICT (scope_name) DO NOTHING;

-- ---------------------------------------------------------------------------------------------------------
-- BEGIN OIDC JWKS Schema
-- ---------------------------------------------------------------------------------------------------------

-- OIDC JSON Web Key Set persistence table
CREATE TABLE IF NOT EXISTS oidc_jwks_keys (
    kid VARCHAR(255) PRIMARY KEY, -- Key ID (unique identifier)
    key_data JSONB NOT NULL, -- JWK data in JSON format
    key_type VARCHAR(10) NOT NULL CHECK (key_type IN ('RSA', 'EC', 'oct')), -- Key type
    algorithm VARCHAR(10) NOT NULL CHECK (algorithm IN ('RS256', 'ES256', 'HS256')), -- Signing algorithm
    key_use VARCHAR(10) NOT NULL DEFAULT 'sig' CHECK (key_use IN ('sig', 'enc')), -- Key usage
    is_active BOOLEAN DEFAULT true, -- Whether this key is currently active
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE, -- Optional expiration for key rotation
    -- Additional metadata
    key_size INTEGER, -- Key size in bits (e.g., 2048 for RSA)
    curve VARCHAR(20) -- EC curve name (for elliptic curve keys)
);

-- OIDC JWKS indexes
CREATE INDEX IF NOT EXISTS idx_oidc_jwks_kid ON oidc_jwks_keys(kid);
CREATE INDEX IF NOT EXISTS idx_oidc_jwks_active ON oidc_jwks_keys(is_active);
CREATE INDEX IF NOT EXISTS idx_oidc_jwks_expires ON oidc_jwks_keys(expires_at);
CREATE INDEX IF NOT EXISTS idx_oidc_jwks_algorithm ON oidc_jwks_keys(algorithm);

-- ---------------------------------------------------------------------------------------------------------
-- END OIDC JWKS Schema
-- ---------------------------------------------------------------------------------------------------------

-- ---------------------------------------------------------------------------------------------------------
-- END OAuth 2.1 Schema
-- ---------------------------------------------------------------------------------------------------------
