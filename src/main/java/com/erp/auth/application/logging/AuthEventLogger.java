package com.erp.auth.application.logging;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Structured security event logging.
 *
 * <p>All authentication events are logged using a consistent key-value schema
 * for readability and automated log parsing:
 *
 * <pre>
 * evento=login_fallido tenant_id=... user_id=... trace_id=... resultado=fallo timestamp=...
 * </pre>
 *
 * <p>The schema strictly disallows passwords, tokens, or secrets: no parameters
 * accept credentials, ensuring audit logs never leak sensitive authentication material.
 *
 * <p>Emitted via the dedicated {@code SECURITY} logger to enable separate retention,
 * filtering, and routing.
 */
public final class AuthEventLogger {

    private static final Logger log = LoggerFactory.getLogger("SECURITY");

    private AuthEventLogger() {
    }

    /**
     * Logs a security event.
     *
     * @param evento    event name in snake_case
     * @param tenantId  workshop tenant identifier, if known
     * @param userId    affected user identifier, if known
     * @param traceId   request trace identifier, if known
     * @param resultado event outcome ({@code ok} or {@code fallo})
     * @param extra     additional non-sensitive attributes
     */
    public static void registrar(String evento,
                                  UUID tenantId,
                                  UUID userId,
                                  String traceId,
                                  String resultado,
                                  Map<String, String> extra) {
        log.info(formatear(evento, tenantId, userId, traceId, resultado, extra));
    }

    /**
     * Formats the event key-value log string. Exposed publicly for testing.
     *
     * @param evento    event name
     * @param tenantId  tenant identifier
     * @param userId    user identifier
     * @param traceId   trace identifier
     * @param resultado outcome
     * @param extra     extra key-value pairs
     * @return formatted log line
     */
    public static String formatear(String evento,
                                   UUID tenantId,
                                   UUID userId,
                                   String traceId,
                                   String resultado,
                                   Map<String, String> extra) {
        Map<String, String> atributos = new LinkedHashMap<>();
        atributos.put("evento", evento);
        atributos.put("tenant_id", tenantId != null ? tenantId.toString() : "-");
        atributos.put("user_id", userId != null ? userId.toString() : "-");
        atributos.put("trace_id", traceId != null && !traceId.isBlank() ? traceId : "-");
        atributos.put("resultado", resultado);
        atributos.put("timestamp", Instant.now().toString());

        if (extra != null) {
            extra.forEach((clave, valor) -> {
                if (clave != null && !clave.isBlank() && valor != null) {
                    atributos.put(clave, valor);
                }
            });
        }

        StringBuilder linea = new StringBuilder();
        atributos.forEach((clave, valor) -> {
            if (linea.length() > 0) {
                linea.append(' ');
            }
            linea.append(clave).append('=').append(valor);
        });
        return linea.toString();
    }
}
