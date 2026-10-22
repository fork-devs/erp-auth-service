package com.erp.auth.support;

import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;

import java.io.IOException;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Arranca una instancia real de PostgreSQL en proceso, para los tests que
 * necesitan verificar el comportamiento de la base de datos y no su
 * simulacion: Row-Level Security, FORCE ROW LEVEL SECURITY, SET LOCAL y
 * restricciones NOT NULL.
 *
 * <p>El entorno de ejecucion no dispone de Docker, de modo que Testcontainers
 * no es viable. {@code embedded-postgres} descarga y arranca una distribucion
 * real de PostgreSQL como proceso nativo.
 *
 * <p>Se mantienen dos credenciales distintas, que es el punto que la suite
 * necesita verificar:
 * <ul>
 *   <li>El <strong>propietario</strong>, con el que corren las migraciones de
 *       Flyway. Es el owner de las tablas.</li>
 *   <li>El <strong>rol de aplicacion</strong> {@code erp_app}, sin privilegios
 *       de propietario, con el que conecta la aplicacion. Es el unico sujeto a
 *       la politica de aislamiento.</li>
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
     * Conexion como el propietario, para las comprobaciones que deben ver todas
     * las filas ignorando la politica de aislamiento.
     */
    public static Connection openOwnerConnection() throws SQLException {
        return java.sql.DriverManager.getConnection(jdbcUrl(), ownerUser, OWNER_PASSWORD);
    }

    /**
     * Conexion como el rol de aplicacion, que es el unico sujeto a la politica
     * de aislamiento.
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
