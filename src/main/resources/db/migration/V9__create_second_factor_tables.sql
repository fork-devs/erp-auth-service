-- =============================================================================
-- ERP AUTH SERVICE - V9: SEGUNDO FACTOR DE AUTENTICACION
-- =============================================================================
-- La columna mfa_enabled existia, pero no habia nada detras: ni el secreto
-- enrolado, ni los codigos de recuperacion, ni ninguna forma de activarlo.
-- El campo era decorativo.
--
-- El secreto del segundo factor se guarda CIFRADO. Un TOTP se verifica a
-- partir del secreto compartido, de modo que quien lo lea puede generar
-- codigos validos: un secreto en claro en la tabla es una credencial mas,
-- con la diferencia de que no caduca.
--
-- Los codigos de recuperacion son de un solo uso: se guardan hasheados, con su
-- estado de consumo y su fecha de caducidad.
--
-- Ver docs/doc-estado-implementacion.md, hallazgo P1 6.18.
-- =============================================================================

ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret_ciphertext TEXT;

-- Contador del ultimo codigo aceptado. Un codigo TOTP vale durante su
-- intervalo y el siguiente: sin registrar cual se acepto por ultima vez, el
-- mismo codigo podria usarse dos veces dentro de esa ventana.
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_last_code_counter BIGINT;

COMMENT ON COLUMN users.mfa_last_code_counter IS
    'Contador del ultimo codigo de segundo factor aceptado. Impide que un codigo se reutilice.';

COMMENT ON COLUMN users.mfa_secret_ciphertext IS
    'Secreto del segundo factor, cifrado. El texto plano NO debe guardarse nunca: quien lo lea puede generar codigos validos.';

CREATE TABLE IF NOT EXISTS recovery_codes (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash   VARCHAR(128) NOT NULL,
    used_at     TIMESTAMP WITH TIME ZONE,
    expires_at  TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- La consulta de recuperacion es por usuario, y la limpieza por caducidad.
CREATE INDEX IF NOT EXISTS idx_recovery_codes_user ON recovery_codes(user_id);
CREATE INDEX IF NOT EXISTS idx_recovery_codes_expires_at ON recovery_codes(expires_at);

COMMENT ON TABLE recovery_codes IS
    'Codigos de recuperacion de un solo uso del segundo factor. Se guardan hasheados.';

-- El rol de ejecucion necesita poder consultar y escribir estas filas.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'erp_app') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE recovery_codes TO erp_app';
        EXECUTE 'GRANT SELECT, UPDATE ON TABLE users TO erp_app';
    END IF;
END
$$;
