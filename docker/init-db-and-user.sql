 -- Create tables, functions, triggers, and indexes for apex
DO $$
BEGIN
   IF NOT EXISTS (
      SELECT FROM pg_catalog.pg_roles
      WHERE rolname = 'test'
   ) THEN
      CREATE USER test WITH PASSWORD 'test';
   END IF;
END $$;

DO $$
BEGIN
   IF NOT EXISTS (
      SELECT FROM pg_database
      WHERE datname = 'authly_test'
   ) THEN
      CREATE DATABASE authly_test;
      GRANT ALL PRIVILEGES ON DATABASE authly_test TO test;
   END IF;
END $$;

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

-- Add to docker/init-db-and-user.sql

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

-- Grant necessary permissions (adjust as needed)
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO test;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO test;
