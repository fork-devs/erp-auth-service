package com.erp.auth.infrastructure.adapter.notification;

import com.erp.auth.domain.model.NotificationMessage;
import com.erp.auth.domain.port.NotificationPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Implementacion por defecto del puerto de notificacion: deja constancia de
 * la entrega, pero no envia nada.
 *
 * <p>Es un marcador de posicion explicito: sin un proveedor de correo
 * conectado, el token de restablecimiento tiene que llegar a su destinatario
 * por otra via. Que conste la entrega permite saber que el flujo se ha
 * recorrido entero.
 *
 * <p>El cuerpo del mensaje NO se registra. En el caso del token de
 * restablecimiento, el cuerpo ES la credencial: escribirla en el registro
 * entregaria el token a cualquiera que pueda leerlo, que es lo mismo que no
 * haber revocado nada.
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
