package com.erp.auth;

import com.erp.auth.support.AbstractPostgresIntegrationTest;
import org.junit.jupiter.api.Test;

/**
 * Application context boots against real embedded PostgreSQL with Flyway
 * migrations applied and schema validated by Hibernate.
 *
 * <p>Test profile no longer uses H2 with create-drop: that profile derived the
 * schema from entities, structurally masking schema drift between migrations
 * and entities. See docs/doc-estado-implementacion.md, findings P0 5.5 and P1 6.6.
 */
class ErpAuthServiceApplicationTests extends AbstractPostgresIntegrationTest {

    @Test
    void elContextoArrancaConElEsquemaMigradoYValidado() {
    }

}
