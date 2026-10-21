-- =============================================================================
-- ERP AUTH SERVICE - V6: TENANT_ID EN LAS TABLAS DE TOKENS
-- =============================================================================
-- refresh_tokens y password_reset_tokens no tenian columna tenant_id, de modo
-- que no podian quedar cubiertas por la politica de Row-Level Security: el
-- material de sesion de un taller era legible desde cualquier otro.
-- Ver docs/doc-estado-implementacion.md, hallazgo P1 6.6.
--
-- El backfill toma el tenant del usuario propietario del token. Es un dato
-- derivado, no una decision: un token pertenece al usuario que lo creo, y el
-- usuario pertenece a un unico taller.
-- =============================================================================

-- --- refresh_tokens ---------------------------------------------------------

ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS tenant_id UUID;

UPDATE refresh_tokens rt
   SET tenant_id = u.tenant_id
  FROM users u
 WHERE u.id = rt.user_id
   AND rt.tenant_id IS NULL;

-- Si quedara alguna fila sin tenant, es un token huerfano de un usuario que
-- no existe: no se puede inventar su tenant, y dejarla nula impediria activar
-- la restriccion NOT NULL. Se falla de forma explicita.
DO $$
DECLARE
    huerfanos INTEGER;
BEGIN
    SELECT count(*) INTO huerfanos
      FROM refresh_tokens
     WHERE tenant_id IS NULL;

    IF huerfanos > 0 THEN
        RAISE EXCEPTION
            'Hay % refresh_tokens sin tenant resoluble: revisar la integridad de users antes de continuar', huerfanos;
    END IF;
END
$$;

ALTER TABLE refresh_tokens ALTER COLUMN tenant_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_tenant ON refresh_tokens(tenant_id);

ALTER TABLE refresh_tokens FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS refresh_tokens_tenant_isolation_policy ON refresh_tokens;

CREATE POLICY refresh_tokens_tenant_isolation_policy ON refresh_tokens
    FOR ALL
    USING (
        tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid
    );

-- --- password_reset_tokens --------------------------------------------------

ALTER TABLE password_reset_tokens ADD COLUMN IF NOT EXISTS tenant_id UUID;

UPDATE password_reset_tokens prt
   SET tenant_id = u.tenant_id
  FROM users u
 WHERE u.id = prt.user_id
   AND prt.tenant_id IS NULL;

DO $$
DECLARE
    huerfanos INTEGER;
BEGIN
    SELECT count(*) INTO huerfanos
      FROM password_reset_tokens
     WHERE tenant_id IS NULL;

    IF huerfanos > 0 THEN
        RAISE EXCEPTION
            'Hay % password_reset_tokens sin tenant resoluble: revisar la integridad de users antes de continuar', huerfanos;
    END IF;
END
$$;

ALTER TABLE password_reset_tokens ALTER COLUMN tenant_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_tenant ON password_reset_tokens(tenant_id);

ALTER TABLE password_reset_tokens FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS password_reset_tokens_tenant_isolation_policy ON password_reset_tokens;

CREATE POLICY password_reset_tokens_tenant_isolation_policy ON password_reset_tokens
    FOR ALL
    USING (
        tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid
    );
