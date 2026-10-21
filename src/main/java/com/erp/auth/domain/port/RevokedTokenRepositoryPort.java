package com.erp.auth.domain.port;

import java.time.Instant;
import java.util.UUID;

/**
 * Registro de tokens de acceso revocados.
 *
 * <p>Un token de acceso solo queda invalidado por su expiracion, y su
 * ventana de expiracion es de quince minutos. Registrar la revocacion
 * permite cerrar la sesion de verdad: la credencial deja de aceptarse aunque
 * no haya expirado.
 *
 * <p>Las entradas se identifican por el identificador unico del token
 * ({@code jti}), que es unico por si mismo.
 */
public interface RevokedTokenRepositoryPort {

    /**
     * Registra la revocacion de un token. Registrar dos veces el mismo
     * token no es un error: la revocacion es idempotente.
     */
    void revoke(UUID tokenId, UUID userId, Instant expiresAt);

    /**
     * Indica si el token ha sido revocado.
     */
    boolean isRevoked(UUID tokenId);

    /**
     * Elimina las entradas cuyo token ya ha expirado. Devuelve el numero de
     * entradas eliminadas.
     */
    int deleteExpired(Instant now);
}
