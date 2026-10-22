-- =============================================================================
-- ERP AUTH SERVICE - V4: ROL DE APLICACION Y PERMISOS
-- =============================================================================
-- Crea el rol con el que conecta la aplicacion en tiempo de ejecucion.
--
-- El rol propietario (POSTGRES_USER / el usuario con el que corren las
-- migraciones) deja de ser el que usa la aplicacion. Motivo: en PostgreSQL el
-- propietario de una tabla ELUDE su politica de Row-Level Security, de modo
-- que con un unico rol la RLS declarada en V3 es inerte. Ver
-- docs/doc-estado-implementacion.md, hallazgo P1 6.6.
--
-- El rol se crea con NOBYPASSRLS para que ningun permiso de la base de
-- datos pueda saltarse la politica de aislamiento por la via del rol.
--
-- Las tablas tienen claves primarias UUID con DEFAULT gen_random_uuid(), por
-- lo que no existen secuencias que granting. El privilegio USAGE sobre el
-- esquema es imprescindible: sin el, el rol no puede resolver ningun objeto
-- aunque tenga privilegios sobre las tablas.
-- =============================================================================

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'erp_app') THEN
        EXECUTE format(
            'CREATE ROLE erp_app LOGIN NOINHERIT NOSUPERUSER NOCREATEDB '
            'NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L',
            '${appRolePassword}'
        );
    END IF;
END
$$;

-- Uso del esquema: sin esto el rol no resuelve los objetos.
GRANT USAGE ON SCHEMA public TO erp_app;

-- Catálogo global de roles: solo lectura, es compartido por todos los tenants.
GRANT SELECT ON TABLE roles TO erp_app;

-- Tablas de negocio por tenant: lectura y escritura, con la RLS como filtro.
-- FORCE ROW LEVEL SECURITY se aplica en la migracion V5.
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE users TO erp_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE user_roles TO erp_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE refresh_tokens TO erp_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE password_reset_tokens TO erp_app;

-- Comprobacion de que el rol queda efectivamente sujeto a la RLS.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_roles
        WHERE rolname = 'erp_app' AND rolbypassrls
    ) THEN
        RAISE EXCEPTION 'El rol erp_app no debe tener BYPASSRLS: la politica de aislamiento seria eludible';
    END IF;
END
$$;
