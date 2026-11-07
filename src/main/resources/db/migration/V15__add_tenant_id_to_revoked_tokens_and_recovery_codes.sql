-- =============================================================================
-- ERP AUTH SERVICE - V15: TENANT_ID EN REVOKED_TOKENS Y RECOVERY_CODES
-- =============================================================================
-- Las tablas revoked_tokens y recovery_codes no tenian columna tenant_id, lo que
-- impedia el scoping por taller y la aplicacion de politicas de Row-Level
-- Security (RLS).
-- =============================================================================

-- --- revoked_tokens ---------------------------------------------------------

ALTER TABLE revoked_tokens ADD COLUMN IF NOT EXISTS tenant_id UUID;

UPDATE revoked_tokens rt
   SET tenant_id = u.tenant_id
  FROM users u
 WHERE u.id = rt.user_id
   AND rt.tenant_id IS NULL;

-- En caso de tablas vacias o registros historicos sin resolver, si existieran filas huerfanas:
DELETE FROM revoked_tokens WHERE tenant_id IS NULL;

ALTER TABLE revoked_tokens ALTER COLUMN tenant_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_revoked_tokens_tenant ON revoked_tokens(tenant_id);

ALTER TABLE revoked_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE revoked_tokens FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS revoked_tokens_tenant_isolation_policy ON revoked_tokens;

CREATE POLICY revoked_tokens_tenant_isolation_policy ON revoked_tokens
    FOR ALL
    USING (
        tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid
    );

-- --- recovery_codes ---------------------------------------------------------

ALTER TABLE recovery_codes ADD COLUMN IF NOT EXISTS tenant_id UUID;

UPDATE recovery_codes rc
   SET tenant_id = u.tenant_id
  FROM users u
 WHERE u.id = rc.user_id
   AND rc.tenant_id IS NULL;

DELETE FROM recovery_codes WHERE tenant_id IS NULL;

ALTER TABLE recovery_codes ALTER COLUMN tenant_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_recovery_codes_tenant ON recovery_codes(tenant_id);

ALTER TABLE recovery_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE recovery_codes FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS recovery_codes_tenant_isolation_policy ON recovery_codes;

CREATE POLICY recovery_codes_tenant_isolation_policy ON recovery_codes
    FOR ALL
    USING (
        tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid
    );

-- --- Permisos para el rol de ejecucion erp_app ------------------------------
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'erp_app') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE revoked_tokens TO erp_app';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE recovery_codes TO erp_app';
    END IF;
END
$$;
