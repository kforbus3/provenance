-- External identity providers (SSO). auth_source marks how an account
-- authenticates: 'local' (password), 'oidc', or 'ldap'. External accounts have
-- no usable local password and are provisioned on first SSO login.

ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_source TEXT NOT NULL DEFAULT 'local';
