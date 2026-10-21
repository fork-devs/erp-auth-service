package com.erp.auth.domain.port;

import com.erp.auth.domain.model.TokenIdentity;
import com.erp.auth.domain.model.User;

import java.time.Duration;
import java.util.Map;
import java.util.UUID;

/**
 * Emision de credenciales.
 *
 * <p>Los tres tipos de token que emite el servicio comparten el mismo
 * conjunto de claims: emisor, **audiencia**, **identificador unico**
 * ({@code jti}), tiempo de emision y tiempo de expiracion. El identificador
 * unico es lo que permite revocar un token concreto, y la audiencia es lo que
 * impide que un token emitido para un servicio se acepte en otro.
 */
public interface TokenSignerPort {

    /**
     * Token de acceso. Lleva ademas el sujeto, el taller, el correo, el
     * nombre y el conjunto de roles.
     */
    String generateAccessToken(User user);

    /**
     * Token de refresco. Lleva el sujeto, el taller y los roles: es lo que
     * permite al servicio saber a quien pertenece sin consultar la base de
     * datos.
     */
    String generateRefreshToken(User user);

    /**
     * Token de restablecimiento de contrasena.
     *
     * <p>NO lleva el sujeto: el token viaja por correo, y un token que
     * revelara la identidad de su titular permitiria a quien lo obtuviera
     * saber a que usuario corresponde. La fila de la base de datos, que se
     * localiza por el hash del token, es la que dice a que usuario pertenece.
     */
    String generatePasswordResetToken(UUID userId);

    String hashToken(String rawToken);

    /**
     * Identificador unico del token emitido, tal como va en su claim
     * {@code jti}. Es lo que hay que registrar para revocar ese token
     * concreto.
     */
    String extractTokenId(String token);

    /**
     * Identidad de un token emitido: identificador unico, titular y fecha de
     * expiracion. Es lo que hace falta para revocarlo.
     */
    TokenIdentity extractIdentity(String token);

    Duration getAccessTokenDuration();

    Duration getRefreshTokenDuration();

    Duration getPasswordResetTokenDuration();

    Map<String, Object> getJwksPublicKeySet();

    /**
     * Audiencia para la que se emiten los tokens. Los verificadores la
     * comprueban: un token emitido para otra audiencia se rechaza.
     */
    String getAudience();
}
