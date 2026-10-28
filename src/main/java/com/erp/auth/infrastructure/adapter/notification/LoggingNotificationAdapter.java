package com.erp.auth.infrastructure.adapter.notification;

import com.erp.auth.domain.model.NotificationMessage;
import com.erp.auth.domain.port.NotificationPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Default fallback implementation of the notification port: records delivery attempts
 * in application logs without external dispatch.
 *
 * <p>Acts as an explicit placeholder when no external email/SMS provider is configured.
 *
 * <p>Message bodies are deliberately NOT logged. For password reset notifications,
 * the body contains the credential token; logging it would leak sensitive tokens into logs.
 */
@Component
public class LoggingNotificationAdapter implements NotificationPort {

    private static final Logger log = LoggerFactory.getLogger(LoggingNotificationAdapter.class);

    @Override
    public void deliver(NotificationMessage notification) {
        log.info("Notificacion pendiente de entrega. Destinatario: {}, asunto: {}, cuerpo: {} caracteres "
                        + "(no se registra el contenido: puede llevar una credencial)",
                notification.recipient(),
                notification.subject(),
                notification.body() != null ? notification.body().length() : 0);
    }
}
