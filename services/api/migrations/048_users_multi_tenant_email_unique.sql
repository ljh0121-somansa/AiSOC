-- Migration 048: Allow same user email across multiple tenants (Multi-Tenant User Support)
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_email_key;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'uq_users_tenant_email'
    ) THEN
        ALTER TABLE users ADD CONSTRAINT uq_users_tenant_email UNIQUE (tenant_id, email);
    END IF;
END $$;
