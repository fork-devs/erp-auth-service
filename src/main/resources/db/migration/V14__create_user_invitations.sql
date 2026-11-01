-- =============================================================================
-- ERP AUTH SERVICE - V14: TABLA DE INVITACIONES DE USUARIOS
-- =============================================================================
-- Soporta el flujo de incorporacion de colaboradores mediante enlace seguro.
-- El token se almacena hasheado (SHA-256) para evitar exposicion en base de datos.
-- =============================================================================

CREATE TABLE IF NOT EXISTS user_invitations (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID NOT NULL,
    email        VARCHAR(255) NOT NULL,
    full_name    VARCHAR(255) NOT NULL,
    role         VARCHAR(50) NOT NULL,
    token_hash   VARCHAR(128) NOT NULL,
    expires_at   TIMESTAMP WITH TIME ZONE NOT NULL,
    accepted_at  TIMESTAMP WITH TIME ZONE NULL,
    created_at   TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_user_invitations_token_hash ON user_invitations(token_hash);
CREATE INDEX IF NOT EXISTS idx_user_invitations_tenant_email ON user_invitations(tenant_id, email);
CREATE INDEX IF NOT EXISTS idx_user_invitations_expires_at ON user_invitations(expires_at);

COMMENT ON TABLE user_invitations IS
    'Invitaciones emitidas para registro y activacion de colaboradores en talleres mediante enlace seguro';

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'erp_app') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE user_invitations TO erp_app';
    END IF;
END
$$;
