package com.erp.auth;

import com.erp.auth.support.AbstractPostgresIntegrationTest;
import org.junit.jupiter.api.Test;

/**
 * El contexto de la aplicacion arranca contra PostgreSQL real embebido, con
 * las migraciones de Flyway aplicadas y el esquema validado por Hibernate.
 *
 * <p>El perfil de test ya no usa H2 con create-drop: ese perfil derivaba el
 * esquema de las entidades, de modo que la deriva entre migracion y entidad
 * era estructuralmente invisible. Ver docs/doc-estado-implementacion.md,
 * hallazgos P0 5.5 y P1 6.6.
 */
class ErpAuthServiceApplicationTests extends AbstractPostgresIntegrationTest {

    @Test
    void elContextoArrancaConElEsquemaMigradoYValidado() {
    }

}
