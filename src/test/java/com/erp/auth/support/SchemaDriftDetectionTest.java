package com.erp.auth.support;

import com.erp.auth.ErpAuthServiceApplication;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.Statement;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Startup against real PostgreSQL must FAIL when the database schema does not match
 * what the JPA mapping expects.
 *
 * <p>With the previous test profile (H2 with create-drop), schema was derived from
 * entities, leaving schema drift and migration bugs undetectable. This test confirms
 * that with migrations applied and hibernate schema validation active, an intentional
 * column rename prevents startup.
 */
class SchemaDriftDetectionTest extends AbstractPostgresIntegrationTest {

    @Test
    void unaMigracionAlteradaImpideElArranque() throws Exception {
        String url = EmbeddedPostgresSupport.jdbcUrl();
        String usuario = EmbeddedPostgresSupport.ownerUser();
        String password = EmbeddedPostgresSupport.ownerPassword();

        // Deliberately drift the schema: the migration declares tenant_id NOT NULL
        // and JPA entities expect it, but renaming it forces schema validation to fail.
        //
        // The embedded database is shared across the suite, so changes are reverted
        // in a finally block to avoid polluting subsequent tests.
        try (Connection connection = java.sql.DriverManager.getConnection(url, usuario, password);
             Statement statement = connection.createStatement()) {
            statement.execute("ALTER TABLE users RENAME COLUMN tenant_id TO tenant_id_alterada");
        }

        try {
            ejecutarContextoAlterado(url, usuario, password);
        } finally {
            try (Connection connection = java.sql.DriverManager.getConnection(url, usuario, password);
                 Statement statement = connection.createStatement()) {
                statement.execute("ALTER TABLE users RENAME COLUMN tenant_id_alterada TO tenant_id");
            }
        }
    }

    private void ejecutarContextoAlterado(String url, String usuario, String password) {

        DataSource dataSource = new DriverManagerDataSource(url, usuario, password);

        new ApplicationContextRunner()
                .withUserConfiguration(ErpAuthServiceApplication.class)
                .withPropertyValues(
                        "spring.datasource.url=" + url,
                        "spring.datasource.username=" + usuario,
                        "spring.datasource.password=" + password,
                        "spring.datasource.driver-class-name=org.postgresql.Driver",
                        "spring.jpa.hibernate.ddl-auto=validate",
                        "spring.flyway.enabled=false",
                        "spring.flyway.baseline-on-migrate=false")
                .withBean(DataSource.class, () -> dataSource)
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure()).hasStackTraceContaining("tenant_id");
                });
    }
}
