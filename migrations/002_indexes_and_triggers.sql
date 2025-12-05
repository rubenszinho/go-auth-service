-- Migration: 002_indexes_and_triggers.sql
-- Description: Add indexes and triggers for performance and data consistency
-- Created: 2025-01-26
-- Dependencies: 001_initial_schema.sql

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_google_id ON users(google_id);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_user_id ON auth_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_expires_at ON auth_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_auth_oauth_accounts_user_id ON auth_oauth_accounts(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_oauth_accounts_provider ON auth_oauth_accounts(provider, provider_id);
CREATE INDEX IF NOT EXISTS idx_auth_refresh_tokens_user_id ON auth_refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_refresh_tokens_token ON auth_refresh_tokens(token);
CREATE INDEX IF NOT EXISTS idx_auth_refresh_tokens_expires_at ON auth_refresh_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_auth_password_resets_token ON auth_password_resets(token);
CREATE INDEX IF NOT EXISTS idx_auth_password_resets_expires_at ON auth_password_resets(expires_at);
CREATE INDEX IF NOT EXISTS idx_auth_email_verifications_token ON auth_email_verifications(token);
CREATE INDEX IF NOT EXISTS idx_auth_email_verifications_expires_at ON auth_email_verifications(expires_at);

-- Create updated_at trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for updated_at
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_auth_sessions_updated_at ON auth_sessions;
CREATE TRIGGER update_auth_sessions_updated_at BEFORE UPDATE ON auth_sessions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_auth_oauth_accounts_updated_at ON auth_oauth_accounts;
CREATE TRIGGER update_auth_oauth_accounts_updated_at BEFORE UPDATE ON auth_oauth_accounts
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_auth_refresh_tokens_updated_at ON auth_refresh_tokens;
CREATE TRIGGER update_auth_refresh_tokens_updated_at BEFORE UPDATE ON auth_refresh_tokens
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_auth_password_resets_updated_at ON auth_password_resets;
CREATE TRIGGER update_auth_password_resets_updated_at BEFORE UPDATE ON auth_password_resets
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_auth_email_verifications_updated_at ON auth_email_verifications;
CREATE TRIGGER update_auth_email_verifications_updated_at BEFORE UPDATE ON auth_email_verifications
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Record this migration
INSERT INTO schema_migrations (version, description) 
VALUES ('002', 'Add indexes and triggers for performance') 
ON CONFLICT (version) DO NOTHING;
