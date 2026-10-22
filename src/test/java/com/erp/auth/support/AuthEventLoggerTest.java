package com.erp.auth.support;

import com.erp.auth.application.logging.AuthEventLogger;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * El registro de eventos de autenticacion.
 *
 * <p>El esquema no admite contrasenas, tokens ni secretos: no hay ningun
 * parametro para ellos. Un registro de autenticacion es un documento de
 * auditoria, y un documento de auditoria con credenciales es un almacen de
 * credenciales.
 */
class AuthEventLoggerTest {

    private ListAppender<ILoggingEvent> appender;
    private Logger logger;

    @BeforeEach
    void setUp() {
        logger = (Logger) LoggerFactory.getLogger("SECURITY");
        appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
    }

    @AfterEach
    void tearDown() {
        logger.detachAppender(appender);
        appender.stop();
    }

    @Test
    @DisplayName("El evento lleva los identificadores y el resultado")
    void elEventoLlevaLosIdentificadoresYElResultado() {
        UUID tenantId = UUID.randomUUID();
        UUID userId = UUID.randomUUID();

        AuthEventLogger.registrar("login_correcto", tenantId, userId, "traza-1", "ok", Map.of());

        String linea = ultimaLinea();
        assertTrue(linea.contains("evento=login_correcto"), linea);
        assertTrue(linea.contains("tenant_id=" + tenantId), linea);
        assertTrue(linea.contains("user_id=" + userId), linea);
        assertTrue(linea.contains("trace_id=traza-1"), linea);
        assertTrue(linea.contains("resultado=ok"), linea);
        assertTrue(linea.contains("timestamp="), linea);
    }

    @Test
    @DisplayName("El registro no contiene contrasenas ni tokens")
    void elRegistroNoContieneContrasenasNiTokens() {
        String contrasena = "MiContrasenaSecreta1!";
        String token = "eyJhbGciOiJSUzI1NiJ9.token.firma";

        AuthEventLogger.registrar("login_fallido", UUID.randomUUID(), UUID.randomUUID(), null, "fallo",
                Map.of("motivo", "credenciales_incorrectas"));

        String linea = ultimaLinea();
        assertFalse(linea.contains(contrasena), "El registro no puede contener la contrasena: " + linea);
        assertFalse(linea.contains(token), "El registro no puede contener el token: " + linea);
        assertFalse(linea.toLowerCase().contains("password"), linea);
        assertFalse(linea.toLowerCase().contains("token="), linea);
    }

    @Test
    @DisplayName("Un evento sin traz ni usuario los deja marcados, no los omite")
    void unEventoSinTrazNiUsuarioLosDejaMarcados() {
        AuthEventLogger.registrar("login_fallido", null, null, null, "fallo", Map.of());

        String linea = ultimaLinea();
        assertTrue(linea.contains("tenant_id=-"), linea);
        assertTrue(linea.contains("user_id=-"), linea);
        assertTrue(linea.contains("trace_id=-"), linea);
    }

    private String ultimaLinea() {
        return appender.list.get(appender.list.size() - 1).getFormattedMessage();
    }
}
