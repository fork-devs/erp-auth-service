-- =============================================================================
-- ERP AUTH SERVICE - V5: ROW-LEVEL SECURITY EFECTIVA
-- =============================================================================
-- Dos correcciones sobre V3:
--
-- 1) FORCE ROW LEVEL SECURITY. En PostgreSQL, ENABLE ROW LEVEL SECURITY NO
--    aplica la politica al propietario de la tabla: el propietario la elude.
--    Con FORCE, tambien se aplica a el. Es imprescindible porque la
--    aplicacion conectaba con el rol propietario.
--    Ver docs/doc-estado-implementacion.md, hallazgo P1 6.6.
--
-- 2) Se elimina el hueco de escape `app.bypass_rls`. Era una session variable
--    que cualquier instruccion SQL podia activar y desactivar el aislamiento
--    por completo. El aislamiento se decide ahora con una sola cosa: el
--    contexto de tenant establecido por la aplicacion.
--
-- La politica es FAIL-CLOSED: si `app.tenant_id` no esta establecido,
--    current_setting devuelve NULL, la comparacion con NULL no es cierta, y la
--    tabla devuelve cero filas. La aplicacion, ademas, aborta la operacion
--    antes de llegar aqui si no encuentra contexto (PostgresTenantRlsAspect).
--
-- Las tablas refresh_tokens y password_reset_tokens reciben su columna
-- tenant_id y su politica en la migracion V6, que debe ejecutarse antes:
-- una politica no puede referenciar una columna que todavia no existe.
-- =============================================================================

-- --- users -----------------------------------------------------------------

ALTER TABLE users FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS users_tenant_isolation_policy ON users;

CREATE POLICY users_tenant_isolation_policy ON users
    FOR ALL
    USING (
        tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid
    );

-- --- user_roles ------------------------------------------------------------
-- La columna tenant_id ya existe desde V1 (NOT NULL, y forma parte de la
-- clave primaria). La migracion V7 se ocupa de su indice.

ALTER TABLE user_roles FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS user_roles_tenant_isolation_policy ON user_roles;

CREATE POLICY user_roles_tenant_isolation_policy ON user_roles
    FOR ALL
    USING (
        tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid
    );

-- --- Comprobacion ----------------------------------------------------------

DO $$
DECLARE
    sin_forzar TEXT;
BEGIN
    SELECT string_agg(c.relname, ', ')
      INTO sin_forzar
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE c.relname IN ('users', 'user_roles')
       AND n.nspname = 'public'
       AND NOT c.relforcerowsecurity;

    IF sin_forzar IS NOT NULL THEN
        RAISE EXCEPTION 'Tablas sin FORCE ROW LEVEL SECURITY: %', sin_forzar;
    END IF;
END
$$;
