package com.erp.auth.support;

import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;

import java.io.IOException;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Starts an in-process real PostgreSQL instance for tests requiring verification
 * of actual database behavior rather than simulations: Row-Level Security,
 * FORCE ROW LEVEL SECURITY, SET LOCAL, and NOT NULL constraints.
 *
 * <p>The execution environment does not have Docker, so Testcontainers is not viable.
 * {@code embedded-postgres} downloads and starts a real PostgreSQL distribution
 * as a native process.
 *
 * <p>Two distinct credentials are maintained, which is what the test suite verifies:
 * <ul>
 *   <li>The <strong>owner</strong>, under which Flyway migrations run and who owns the tables.</li>
 *   <li>The <strong>application role</strong> {@code erp_app}, without owner privileges,
 *       used by the application connection. It is the only role subject to the isolation policy.</li>
 * </ul>
 */
public final class EmbeddedPostgresSupport {

    public static final String APP_ROLE = "erp_app";
    public static final String APP_PASSWORD = "erp_app_test_password";
    public static final String OWNER_PASSWORD = "erp_owner_test_password";
    public static final String DATABASE = "postgres";

    private static EmbeddedPostgres postgres;
    private static String jdbcUrl;
    private static String ownerUser;

    private EmbeddedPostgresSupport() {
    }

    public static synchronized void start() {
        if (postgres != null) {
            return;
        }
        try {
            postgres = EmbeddedPostgres.builder()
                    .setServerConfig("listen_addresses", "localhost")
                    .setServerConfig("fsync", "off")
                    .setServerConfig("full_page_writes", "off")
                    .setServerConfig("synchronous_commit", "off")
                    .start();

            ownerUser = resolveOwnerUser();
            jdbcUrl = postgres.getJdbcUrl(DATABASE, ownerUser).split("[?]")[0];

            try (Connection connection = postgres.getPostgresDatabase().getConnection();
                 Statement statement = connection.createStatement()) {
                statement.execute("ALTER ROLE \"" + ownerUser + "\" WITH PASSWORD '" + OWNER_PASSWORD + "'");
            }
        } catch (IOException | SQLException e) {
            throw new IllegalStateException("No se pudo arrancar PostgreSQL embebido para los tests", e);
        }
    }

    public static synchronized void stop() {
        if (postgres == null) {
            return;
        }
        try {
            postgres.close();
        } catch (IOException e) {
            throw new IllegalStateException("No se pudo detener PostgreSQL embebido", e);
        } finally {
            postgres = null;
            jdbcUrl = null;
            ownerUser = null;
        }
    }

    public static String jdbcUrl() {
        start();
        return jdbcUrl;
    }

    public static String ownerUser() {
        start();
        return ownerUser;
    }

    public static String ownerPassword() {
        return OWNER_PASSWORD;
    }

    public static String appRole() {
        return APP_ROLE;
    }

    public static String appPassword() {
        return APP_PASSWORD;
    }

    /**
     * Connection as the owner, for checks that must inspect all rows ignoring the isolation policy.
     */
    public static Connection openOwnerConnection() throws SQLException {
        return java.sql.DriverManager.getConnection(jdbcUrl(), ownerUser, OWNER_PASSWORD);
    }

    /**
     * Connection as the application role, which is the only role subject to the isolation policy.
     */
    public static Connection openAppConnection() throws SQLException {
        return java.sql.DriverManager.getConnection(jdbcUrl(), APP_ROLE, APP_PASSWORD);
    }

    private static String resolveOwnerUser() throws SQLException {
        try (Connection connection = postgres.getPostgresDatabase().getConnection()) {
            return connection.getMetaData().getUserName();
        }
    }
}
