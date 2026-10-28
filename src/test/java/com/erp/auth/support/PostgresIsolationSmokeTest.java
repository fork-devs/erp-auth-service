package com.erp.auth.support;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies that the test database is a real PostgreSQL instance with active
 * Row-Level Security, and that the application database role is subject to that isolation.
 */
class PostgresIsolationSmokeTest extends AbstractPostgresIntegrationTest {

    @Autowired
    private DataSource dataSource;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Test
    void laMigracionSeAplicaSobrePostgresReal() throws Exception {
        Integer total = jdbcTemplate.queryForObject("SELECT count(*) FROM users", Integer.class);
        assertEquals(0, total, "La tabla users deberia estar vacia recien migrada");
    }

    @Test
    void elRolDeAplicacionNoEsElPropietarioYEstaSujetoAlAislamiento() throws Exception {
        try (Connection connection = EmbeddedPostgresSupport.openAppConnection();
             Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery(
                     "SELECT r.rolsuper, r.rolbypassrls, (SELECT count(*) FROM pg_class c "
                     + "JOIN pg_namespace n ON n.oid = c.relnamespace "
                     + "WHERE n.nspname = 'public' AND c.relname = 'users' AND c.relowner = r.oid) AS owner_de_users "
                     + "FROM pg_roles r WHERE r.rolname = 'erp_app'")) {
            rs.next();
            assertFalse(rs.getBoolean("rolsuper"), "El rol de aplicacion no debe ser superusuario");
            assertFalse(rs.getBoolean("rolbypassrls"), "El rol de aplicacion no debe poder eludir la RLS");
            assertEquals(0, rs.getInt("owner_de_users"), "El rol de aplicacion no debe ser el propietario de users");
        }
    }

    @Test
    void laPoliticaDeAislamientoEstaActivaYEsFailClosed() throws Exception {
        try (Connection connection = EmbeddedPostgresSupport.openAppConnection();
             Statement statement = connection.createStatement()) {
            // Without tenant context, writes are rejected: isolation is fail-closed
            // for write operations as well as reads.
            assertThrows(SQLException.class, () -> statement.execute(
                    "INSERT INTO users (id, tenant_id, email, password_hash) VALUES "
                    + "('11111111-1111-1111-1111-111111111111', "
                    + "'22222222-2222-2222-2222-222222222222', 'a@b.com', 'hash')"));

            // With the owner tenant context, the insert succeeds.
            statement.execute("BEGIN");
            statement.execute("SET LOCAL app.tenant_id = '22222222-2222-2222-2222-222222222222'");
            statement.execute("INSERT INTO users (id, tenant_id, email, password_hash) VALUES "
                    + "('11111111-1111-1111-1111-111111111111', "
                    + "'22222222-2222-2222-2222-222222222222', 'a@b.com', 'hash')");

            // With the owner tenant context, its row is visible.
            try (ResultSet rs = statement.executeQuery("SELECT count(*) FROM users")) {
                rs.next();
                assertEquals(1, rs.getInt(1), "Con el contexto del tenant debe verse su fila");
            }
            statement.execute("COMMIT");

            // Once the transaction ends, the context is cleared and no rows are visible.
            try (ResultSet rs = statement.executeQuery("SELECT count(*) FROM users")) {
                rs.next();
                assertEquals(0, rs.getInt(1), "Sin app.tenant_id no debe verse ninguna fila");
            }
        }
    }

    @Test
    void lasTablasDeNegocioTienenLaRlsHabilitadaYForzada() throws Exception {
        try (Connection connection = EmbeddedPostgresSupport.openOwnerConnection();
             Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery(
                     "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                     + "WHERE n.nspname = 'public' AND c.relname IN "
                     + "('users','user_roles','refresh_tokens','password_reset_tokens') "
                     + "AND NOT (c.relrowsecurity AND c.relforcerowsecurity)")) {
            assertFalse(rs.next(),
                    "Todas las tablas de negocio deben tener la RLS habilitada Y forzada: "
                    + "FORCE por si solo no habilita la politica");
        }
    }
}
