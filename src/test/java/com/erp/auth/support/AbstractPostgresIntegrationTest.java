package com.erp.auth.support;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * Base de los tests de integracion del servicio de autenticacion.
 *
 * <p>Arranca PostgreSQL real en proceso y conecta la aplicacion con el rol de
 * runtime {@code erp_app}, que es el unico sujeto a la politica de
 * Row-Level Security. Las migraciones de Flyway las ejecuta el propietario.
 */
@SpringBootTest
public abstract class AbstractPostgresIntegrationTest {

    @DynamicPropertySource
    static void registerPostgresProperties(DynamicPropertyRegistry registry) {
        EmbeddedPostgresSupport.start();

        registry.add("spring.datasource.url", EmbeddedPostgresSupport::jdbcUrl);
        registry.add("spring.datasource.username", EmbeddedPostgresSupport::appRole);
        registry.add("spring.datasource.password", EmbeddedPostgresSupport::appPassword);
        // El perfil de test por defecto fija el driver de H2, que no acepta la URL de PostgreSQL.
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");

        registry.add("spring.flyway.url", EmbeddedPostgresSupport::jdbcUrl);
        registry.add("spring.flyway.user", EmbeddedPostgresSupport::ownerUser);
        registry.add("spring.flyway.password", EmbeddedPostgresSupport::ownerPassword);
        registry.add("spring.flyway.placeholders.appRolePassword", EmbeddedPostgresSupport::appPassword);

        registry.add("spring.jpa.hibernate.ddl-auto", () -> "validate");
        registry.add("spring.flyway.enabled", () -> "true");

        // El material de firma persiste: el servicio lo lee de la fuente
        // configurada y falla al arrancar si no esta.
        registry.add("erp.security.jwt.private-key-pem", TestKeyMaterial::privateKeyPem);
        registry.add("erp.security.jwt.public-key-pem", TestKeyMaterial::publicKeyPem);
    }
}
