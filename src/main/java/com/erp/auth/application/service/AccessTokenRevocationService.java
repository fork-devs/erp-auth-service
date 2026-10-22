package com.erp.auth.application.service;

import com.erp.auth.application.usecase.RevokeAccessTokenUseCase;
import com.erp.auth.domain.model.TokenIdentity;
import com.erp.auth.domain.port.RevokedTokenRepositoryPort;
import com.erp.auth.domain.port.TokenSignerPort;
import com.erp.auth.domain.port.UnitOfWork;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Revocacion de tokens de acceso.
 *
 * <p>La revocacion se registra con la fecha de expiracion del token, de modo
 * que la entrada pueda limpiarse sola cuando el token caduque: un registro de
 * revocacion que no caduca seria una tabla que crece sin limite.
 */
public class AccessTokenRevocationService implements RevokeAccessTokenUseCase {

    private static final Logger log = LoggerFactory.getLogger(AccessTokenRevocationService.class);

    private final RevokedTokenRepositoryPort revokedTokenRepositoryPort;
    private final TokenSignerPort tokenSignerPort;
    private final UnitOfWork unitOfWork;

    public AccessTokenRevocationService(
            RevokedTokenRepositoryPort revokedTokenRepositoryPort,
            TokenSignerPort tokenSignerPort,
            UnitOfWork unitOfWork) {
        this.revokedTokenRepositoryPort = revokedTokenRepositoryPort;
        this.tokenSignerPort = tokenSignerPort;
        this.unitOfWork = unitOfWork;
    }

    @Override
    public void revokeAccessToken(String accessToken) {
        if (accessToken == null || accessToken.isBlank()) {
            return;
        }

        TokenIdentity identity;
        try {
            identity = tokenSignerPort.extractIdentity(accessToken);
        } catch (Exception e) {
            // Un token que no se puede leer no se puede revocar, pero tampoco
            // es un error: lo que se revoca es una credencial que ya no
            // sirve para nada.
            log.debug("El token presentado no se pudo leer, no hay nada que revocar: {}", e.getMessage());
            return;
        }

        unitOfWork.runInTransaction(() ->
                revokedTokenRepositoryPort.revoke(identity.tokenId(), identity.userId(), identity.expiresAt()));

        log.info("Token de acceso revocado para el usuario {}", identity.userId());
    }
}
