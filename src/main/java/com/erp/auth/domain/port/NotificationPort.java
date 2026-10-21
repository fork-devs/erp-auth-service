package com.erp.auth.domain.port;

import com.erp.auth.domain.model.NotificationMessage;

/**
 * Entrega de una notificacion a un destinatario.
 *
 * <p>Es un puerto del dominio, y no depende de ningun proveedor: no sabe de
 * correo, ni de SMS, ni de mensajeria. El adaptador de infraestructura es
 * quien decide como se entrega.
 *
 * <p>Existe para que el token de restablecimiento de contrasena llegue a su
 * destinatario. Devolverlo en la respuesta de la API no es una solucion: la
 * respuesta la ve quien pide el restablecimiento, y con ella se puede
 * restablecer la contrasena de cualquier cuenta.
 */
public interface NotificationPort {

    void deliver(NotificationMessage notification);
}
