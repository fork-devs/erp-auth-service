-- =============================================================================
-- ERP AUTH SERVICE - V8: TOKENS DE ACCESO REVOCADOS
-- =============================================================================
-- El cierre de sesion revocaba el token de REFRESCO, pero no el de acceso.
-- El token de acceso es el que travels con cada peticion, y su vida util la
-- fijaba solo su expiracion: no habia forma de invalidarlo antes de que
-- expirara. Un token robado era valido durante toda la ventana de expiracion.
--
-- El token de acceso lleva un identificador unico (jti). Esta tabla registra
-- los identificadores de los tokens revocados, con la fecha de expiracion del
-- token, para que las entradas caducadas se puedan limpiar solas.
--
-- La tabla NO lleva tenant_id a proposito: la revocacion es de una
-- credencial, no de una fila de negocio de un taller. La consulta de
-- revocacion es por identificador de token, que es unico por si mismo.
--
-- Ver docs/doc-estado-implementacion.md, hallazgo P1 6.20.
-- =============================================================================

CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti         UUID PRIMARY KEY,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at  TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- La tarea de limpieza busca por fecha de expiracion: sin este indice, cada
-- ejecucion recorre la tabla entera.
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_expires_at ON revoked_tokens(expires_at);

COMMENT ON TABLE revoked_tokens IS
    'Tokens de acceso revocados, identificados por su jti. Las entradas cuyo token ya expiro se eliminan.';

-- El rol de ejecucion necesita poder consultar y registrar revocaciones.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'erp_app') THEN
        EXECUTE 'GRANT SELECT, INSERT, DELETE ON TABLE revoked_tokens TO erp_app';
    END IF;
END
$$;
