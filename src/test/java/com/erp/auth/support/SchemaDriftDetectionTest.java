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
 * El arranque contra PostgreSQL real tiene que FALLAR cuando el esquema no
 * coincide con el que espera el codigo.
 *
 * <p>Con el perfil de test anterior (H2 con create-drop) el esquema se
 * derivaba de las entidades, de modo que una migracion alterada nunca se
 * detectaba. Este test comprueba que, con las migraciones aplicadas y el
 * esquema validado, una alteracion deliberada impide el arranque.
 */
class SchemaDriftDetectionTest extends AbstractPostgresIntegrationTest {

    @Test
    void unaMigracionAlteradaImpideElArranque() throws Exception {
        String url = EmbeddedPostgresSupport.jdbcUrl();
        String usuario = EmbeddedPostgresSupport.ownerUser();
        String password = EmbeddedPostgresSupport.ownerPassword();

        // Se altera el esquema de forma deliberada: la migracion declara
        // tenant_id NOT NULL y el codigo lo espera, pero la columna se
        // renombra, con lo que la validacion de esquema debe fallar.
        //
        // La base embebida es compartida por toda la suite, de modo que la
        // alteracion se revierte al terminar: de lo contrario, el resto de
        // los tests se ejecutaria contra un esquema alterado.
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
