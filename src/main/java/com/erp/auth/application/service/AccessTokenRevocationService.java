package com.erp.auth.application.service;

import com.erp.auth.application.logging.AuthEventLogger;
import com.erp.auth.application.usecase.RevokeAccessTokenUseCase;
import com.erp.auth.domain.model.TokenIdentity;
import com.erp.auth.domain.port.RevokedTokenRepositoryPort;
import com.erp.auth.domain.port.TokenSignerPort;
import com.erp.auth.domain.port.UnitOfWork;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

/**
 * Access token revocation service.
 *
 * <p>Revocation is recorded alongside the token's expiration timestamp, allowing
 * the entry to be automatically purged once the token has naturally expired and
 * preventing unbounded table growth.
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
            // A token that cannot be parsed cannot be revoked, but is not an error:
            // the credential is invalid or malformed and cannot be used anyway.
            log.debug("El token presentado no se pudo leer, no hay nada que revocar: {}", e.getMessage());
            return;
        }

        unitOfWork.runInTransaction(() ->
                revokedTokenRepositoryPort.revoke(identity.tokenId(), identity.userId(), identity.expiresAt()));

        AuthEventLogger.registrar("token_acceso_revocado", null, identity.userId(), null, "ok", Map.of());
        log.info("Token de acceso revocado para el usuario {}", identity.userId());
    }
}
