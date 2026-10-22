package com.erp.auth.domain;

import com.erp.auth.domain.port.SecondFactorPort;
import com.erp.auth.domain.port.SecondFactorRepositoryPort;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * El puerto del segundo factor no arrastra dependencias al dominio.
 *
 * <p>El dominio no depende de framework ni de la biblioteca concreta de
 * verificacion: eso es lo que permite que la implementacion cambie sin
 * tocar los casos de uso.
 */
class SecondFactorPortPurityTest {

    @Test
    @DisplayName("El puerto del segundo factor no importa framework ni la biblioteca concreta")
    void elPuertoNoImportaFrameworkNiBiblioteca() throws IOException {
        Path puerto = Paths.get("src/main/java/com/erp/auth/domain/port/SecondFactorPort.java");
        Path persistencia = Paths.get("src/main/java/com/erp/auth/domain/port/SecondFactorRepositoryPort.java");

        assertTrue(Files.exists(puerto), "No se encuentra el puerto del segundo factor");
        assertFalse(contiene(puerto, "org.springframework"),
                "El puerto no puede depender de Spring");
        assertFalse(contiene(puerto, "com.warrenstrange"),
                "El puerto no puede depender de la biblioteca concreta de verificacion");
        assertFalse(contiene(persistencia, "org.springframework"),
                "El puerto de persistencia no puede depender de Spring");
        assertFalse(contiene(persistencia, "com.warrenstrange"),
                "El puerto de persistencia no puede depender de la biblioteca concreta");
    }

    @Test
    @DisplayName("El paquete de dominio no importa Spring en ningun fichero")
    void elPaqueteDeDominioNoImportaSpring() throws IOException {
        Path dominio = Paths.get("src/main/java/com/erp/auth/domain");

        try (Stream<Path> ficheros = Files.walk(dominio)) {
            boolean hayImportDeSpring = ficheros
                    .filter(p -> p.toString().endsWith(".java"))
                    .anyMatch(p -> {
                        try {
                            return contiene(p, "import org.springframework");
                        } catch (IOException e) {
                            throw new IllegalStateException(e);
                        }
                    });
            assertFalse(hayImportDeSpring,
                    "El dominio no debe importar Spring: la regla es que la capa de aplicacion y el "
                            + "dominio no dependan del framework");
        }
    }

    private boolean contiene(Path fichero, String texto) throws IOException {
        return Files.readString(fichero, StandardCharsets.UTF_8).contains(texto);
    }
}
