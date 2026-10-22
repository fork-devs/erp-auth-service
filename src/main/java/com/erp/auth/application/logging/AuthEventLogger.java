package com.erp.auth.application.logging;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Registro estructurado de los eventos de seguridad.
 *
 * <p>Todos los eventos de autenticacion se emiten con el MISMO esquema, de
 * forma que un registro se puede leer de un vistazo y se puede consultar de
 * forma automatizada:
 *
 * <pre>
 * evento=login_fallido tenant_id=... user_id=... trace_id=... resultado=fallo timestamp=...
 * </pre>
 *
 * <p>El esquema NO admite contrasenas, tokens ni secretos: no hay ningun
 * parametro para ellos, de modo que no se pueden colar por descuido. Un
 * registro de autenticacion es un documento de auditoria, y un documento de
 * auditoria que contiene credenciales es un almacen de credenciales.
 *
 * <p>El registro va al logger {@code SECURITY}, separado del registro de
 * aplicacion, de modo que se pueda filtrar, retener o enviar a otro destino
 * sin tocar el resto.
 */
public final class AuthEventLogger {

    private static final Logger log = LoggerFactory.getLogger("SECURITY");

    private AuthEventLogger() {
    }

    /**
     * Registra un evento de seguridad.
     *
     * @param evento    nombre del evento, en snake_case
     * @param tenantId  taller al que pertenece el principal, si se sabe
     * @param userId    principal afectado, si se sabe
     * @param traceId   identificador de traza de la peticion, si se sabe
     * @param resultado {@code ok} o {@code fallo}
     * @param extra     atributos adicionales, que no pueden contener credenciales
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
     * La linea del evento. Es publica para que se pueda comprobar sin
     * depender del sistema de registro.
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
