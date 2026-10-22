package com.erp.auth.infrastructure.health;

import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.stereotype.Component;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

/**
 * Comprobacion de salud de la base de datos.
 *
 * <p>No se limita a decir que hay una conexion configurada: abre una, ejecuta
 * una consulta y la cierra. Un servicio cuyo pool de conexiones esta roto
 * esta vivo, pero no sirve de nada, y la comprobacion de salud tiene que
 * distinguir los dos casos.
 */
@Component("database")
public class DatabaseHealthIndicator implements HealthIndicator {

    private final DataSource dataSource;

    public DatabaseHealthIndicator(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @Override
    public Health health() {
        long inicio = System.currentTimeMillis();
        try (Connection connection = dataSource.getConnection();
             Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery("SELECT 1")) {
            boolean responde = rs.next();
            long milis = System.currentTimeMillis() - inicio;

            if (!responde) {
                return Health.down()
                        .withDetail("comprobacion", "La consulta de salud no devolvio filas")
                        .withDetail("latenciaMs", milis)
                        .build();
            }

            return Health.up()
                    .withDetail("comprobacion", "SELECT 1")
                    .withDetail("latenciaMs", milis)
                    .withDetail("producto", connection.getMetaData().getDatabaseProductName())
                    .build();
        } catch (Exception e) {
            return Health.down(e)
                    .withDetail("comprobacion", "No se pudo abrir la conexion")
                    .withDetail("latenciaMs", System.currentTimeMillis() - inicio)
                    .build();
        }
    }
}
