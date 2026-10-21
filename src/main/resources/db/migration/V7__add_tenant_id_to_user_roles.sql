-- =============================================================================
-- ERP AUTH SERVICE - V7: AISLAMIENTO DE user_roles
-- =============================================================================
-- NOTA SOBRE EL ALCANCE DE ESTA MIGRACION
--
-- La planificacion de este change asumia que user_roles NO tenia columna
-- tenant_id y que habia que crearla, hacer el backfill, pasarla a NOT NULL e
-- incluirla en la clave primaria. Al revisar el esquema real (V1) se comprobo
-- que las cuatro cosas ya estaban hechas desde V1:
--
--   user_roles (
--       user_id  UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
--       role_id  UUID NOT NULL REFERENCES roles(id)  ON DELETE CASCADE,
--       tenant_id UUID NOT NULL,
--       created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
--       PRIMARY KEY (user_id, role_id, tenant_id)
--   )
--
-- Por tanto esta migracion NO crea la columna: comprueba que existe y que es
-- NOT NULL (fallando de forma explicita si el esquema no es el esperado), y
-- hace el trabajo que si queda pendiente para el aislamiento:
--
--   1) Corregir cualquier fila cuyo tenant no coincida con el de su usuario.
--      La columna se rellenaba a mano en la base y nada garantizaba la
--      coherencia con users.tenant_id.
--   2) Crear el indice por tenant_id, del que depende el filtro de la
--      politica de Row-Level Security: sin el, cada consulta de la tabla
--      seria un recorrido completo.
--
-- El defecto real que impedia registrar usuarios NO era el esquema, sino el
-- mapeo JPA, que no incluia la columna en el @JoinTable y por tanto generaba
-- un INSERT sin ella contra una columna NOT NULL. Ese mapeo se corrige en el
-- codigo, no en el esquema.
-- =============================================================================

-- --- Comprobacion del esquema esperado --------------------------------------

DO $$
DECLARE
    existe BOOLEAN;
    es_not_null BOOLEAN;
BEGIN
    SELECT TRUE INTO existe
      FROM information_schema.columns
     WHERE table_schema = 'public'
       AND table_name = 'user_roles'
       AND column_name = 'tenant_id';

    IF NOT existe THEN
        RAISE EXCEPTION 'user_roles.tenant_id no existe: el esquema no es el esperado por esta migracion';
    END IF;

    SELECT is_nullable = 'NO' INTO es_not_null
      FROM information_schema.columns
     WHERE table_schema = 'public'
       AND table_name = 'user_roles'
       AND column_name = 'tenant_id';

    IF NOT es_not_null THEN
        RAISE EXCEPTION 'user_roles.tenant_id debe ser NOT NULL: el aislamiento depende de que no admita nulos';
    END IF;
END
$$;

-- --- Correccion de coherencia ------------------------------------------------

UPDATE user_roles ur
   SET tenant_id = u.tenant_id
  FROM users u
 WHERE u.id = ur.user_id
   AND ur.tenant_id IS DISTINCT FROM u.tenant_id;

-- --- Indice del filtro de aislamiento ----------------------------------------

CREATE INDEX IF NOT EXISTS idx_user_roles_tenant ON user_roles(tenant_id);
