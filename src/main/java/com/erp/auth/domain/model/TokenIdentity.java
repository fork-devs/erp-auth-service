package com.erp.auth.domain.model;

import java.time.Instant;
import java.util.UUID;

/**
 * Identidad de un token de acceso.
 *
 * <p>Es lo que se necesita para revocarlo: su identificador unico, que es
 * la clave del registro de revocacion, su titular, y la fecha en que caduca
 * el token, que es la que permite limpiar el registro cuando ya no sirve
 * para nada.
 */
public record TokenIdentity(
        UUID tokenId,
        UUID userId,
        Instant expiresAt
) {
}
