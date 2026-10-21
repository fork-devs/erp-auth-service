-- =============================================================================
-- ERP AUTH SERVICE - V11: CONTROL DE CONCURRENCIA EN LA FILA DE USUARIO
-- =============================================================================
-- El contador de intentos fallidos se incrementaba con un lectura-modificacion
-- -escritura: dos intentos de inicio de sesion concurrentes sobre la misma
-- cuenta leian el mismo valor y escribian el mismo incremento. El contador
-- perdia los incrementos, de modo que una cuenta con cinco intentos de
-- bloqueo podia Stay desbloqueada tras muchos mas.
--
-- La columna version permite el control de concurrencia optimista: dos
-- escrituras concurrentes sobre la misma fila no pueden ambas tener exito, y
-- la segunda recibe un conflicto explicito en lugar de pisar a la primera.
--
-- Ver docs/doc-estado-implementacion.md, hallazgo P1 6.23.
-- =============================================================================

ALTER TABLE users ADD COLUMN IF NOT EXISTS version BIGINT NOT NULL DEFAULT 0;

COMMENT ON COLUMN users.version IS
    'Control de concurrencia optimista. Dos escrituras concurrentes sobre la misma fila no pueden ambas tener exito.';
