-- =============================================================================
-- ERP AUTH SERVICE - V10: IDENTIDAD ACOTADA AL TALLER
-- =============================================================================
-- El correo era UNIQUE global: una sola cuenta podia existir en toda la
-- plataforma. En un sistema multi-inquilino eso rompe el aislamiento de dos
-- maneras:
--
--   1. Un taller no puede registrar a su propio empleado con el mismo
--      correo que tiene en otro taller. La identidad del usuario queda atada
--      a la plataforma en lugar de al taller.
--   2. El UNIQUE global revela la existencia de una cuenta ajena: el
--      intento de registro falla con un conflicto de unicidad, lo que
--      permite enumerar las cuentas de otros talleres.
--
-- La unicidad pasa a ser POR TALLER: el mismo correo puede existir en
-- talleres distintos, y no puede existir dos veces en el mismo taller.
--
-- ANTES de quitar el indice global, esta migracion COMPRUEBA que no haya
-- correos duplicados entre talleres. Si los hay, la migracion FALLA y los
-- enumera: resolverlos automaticamente seria decidir, sin criterio, a que
-- taller pertenece cada cuenta duplicada. La decision es de negocio, y el
-- error de la migracion la hace visible sin tomarla por el usuario.
--
-- Ver docs/doc-estado-implementacion.md, hallazgo P1 6.22.
-- =============================================================================

DO $$
DECLARE
    duplicados TEXT;
BEGIN
    SELECT string_agg(detalle, E'\n  ') INTO duplicados
      FROM (
            SELECT lower(email) AS correo,
                   count(DISTINCT tenant_id) AS talleres,
                   string_agg(DISTINCT tenant_id::text, ', ' ORDER BY tenant_id::text) AS detalle
              FROM users
             GROUP BY lower(email)
            HAVING count(DISTINCT tenant_id) > 1
           ) duplicados;

    IF duplicados IS NOT NULL THEN
        RAISE EXCEPTION 'Hay correos electronicos registrados en mas de un taller. '
                        'La unicidad pasa a ser por taller, y estos correos habria que resolverlos '
                        'antes de continuar. No se resuelven automaticamente: la pertenencia de cada '
                        'cuenta es una decision de negocio. Correos duplicados: %', duplicados;
    END IF;
END
$$;

-- Se suprime el indice UNIQUE global. La restriccion la impone ahora el
-- indice compuesto de mas abajo, y la columna se queda sin unicidad global.
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_email_key;

-- Unicidad por taller: el mismo correo puede existir en talleres distintos,
-- pero no dos veces en el mismo taller.
--
-- El indice es sobre la columna tal cual, y no sobre lower(email): el valor
-- de correo se normaliza a minusculas en el dominio ANTES de guardarse, de
-- modo que la columna ya esta normalizada y el indice sirve a la consulta.
CREATE UNIQUE INDEX IF NOT EXISTS uk_users_tenant_email ON users(tenant_id, email);
