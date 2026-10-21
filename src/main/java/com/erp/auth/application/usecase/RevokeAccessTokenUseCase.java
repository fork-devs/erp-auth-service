package com.erp.auth.application.usecase;

/**
 * Revocacion de un token de acceso.
 *
 * <p>Cerrar la sesion no puede limitarse a revocar el token de refresco: el
 * token de acceso es el que viaja con cada peticion, y mientras no expire
 * sigue siendo una credencial valida.
 */
public interface RevokeAccessTokenUseCase {

    /**
     * Revoca el token de acceso presented. Un token invalido o ya expirado
     * no es un error: la revocacion de algo que ya no sirve es idempotente.
     */
    void revokeAccessToken(String accessToken);
}
