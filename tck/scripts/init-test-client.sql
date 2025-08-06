-- Initialize OIDC Conformance Test Client
-- This script runs automatically when the PostgreSQL container starts

-- Wait for the oauth_clients table to exist
DO $$
BEGIN
    -- Check if oauth_clients table exists
    IF EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_schema = 'public' 
        AND table_name = 'oauth_clients'
    ) THEN
        -- Insert or update the conformance test client
        INSERT INTO oauth_clients (
            client_id, 
            client_secret, 
            client_name,
            client_type,
            redirect_uris, 
            grant_types,
            response_types,
            scope,
            require_auth_time,
            require_pkce,
            application_type,
            token_endpoint_auth_method,
            id_token_signed_response_alg,
            subject_type
        ) VALUES (
            'oidc-conformance-test',
            '$2b$12$GBfPWJwm.sYwqz8wqMlpVOKr3KRT1YoQQhVxXhzN0D91Kjzvm1Mfi', -- bcrypt hash of 'conformance-test-secret'
            'OIDC Conformance Test Client',
            'confidential',
            ARRAY[
                'https://localhost:8443/test/a/authly/callback',
                'https://localhost:8443/test/a/authly/callback/implicit',
                'https://localhost:8443/test/a/authly/callback/hybrid',
                'https://localhost.emobix.co.uk:8443/test/a/authly/callback',
                'https://localhost.emobix.co.uk:8443/test/a/authly/callback/implicit',
                'https://localhost.emobix.co.uk:8443/test/a/authly/callback/hybrid'
            ]::text[],
            ARRAY['authorization_code', 'refresh_token', 'implicit']::text[],
            ARRAY[
                'code', 
                'code id_token', 
                'code token', 
                'code id_token token', 
                'id_token', 
                'id_token token', 
                'token'
            ]::text[],
            'openid profile email phone address offline_access',
            true,  -- require_auth_time
            true,  -- require_pkce (OAuth 2.1 compliance)
            'web',
            'client_secret_basic',
            'RS256',
            'public'
        ) ON CONFLICT (client_id) DO UPDATE SET
            client_secret = EXCLUDED.client_secret,
            client_name = EXCLUDED.client_name,
            redirect_uris = EXCLUDED.redirect_uris,
            grant_types = EXCLUDED.grant_types,
            response_types = EXCLUDED.response_types,
            scope = EXCLUDED.scope,
            require_auth_time = EXCLUDED.require_auth_time,
            require_pkce = EXCLUDED.require_pkce,
            application_type = EXCLUDED.application_type,
            token_endpoint_auth_method = EXCLUDED.token_endpoint_auth_method,
            id_token_signed_response_alg = EXCLUDED.id_token_signed_response_alg,
            subject_type = EXCLUDED.subject_type,
            updated_at = CURRENT_TIMESTAMP;

        RAISE NOTICE 'OIDC conformance test client initialized successfully';
    ELSE
        RAISE NOTICE 'oauth_clients table does not exist yet, skipping test client creation';
    END IF;
END $$;