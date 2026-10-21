package com.erp.auth.domain.model;

import java.time.Instant;

/**
 * Mensaje de notificacion que hay que entregar a un destinatario.
 *
 * <p>Es un modelo del dominio, no de un proveedor: no sabe de SMTP, ni de
 * correo, ni de SMS. El adaptador de infraestructura es quien decide como se
 * entrega.
 */
public record NotificationMessage(
        String recipient,
        String subject,
        String body,
        Instant createdAt
) {

    public static NotificationMessage of(String recipient, String subject, String body) {
        return new NotificationMessage(recipient, subject, body, Instant.now());
    }
}
