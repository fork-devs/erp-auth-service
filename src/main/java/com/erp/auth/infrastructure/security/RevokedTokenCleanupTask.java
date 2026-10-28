package com.erp.auth.infrastructure.security;

import com.erp.auth.domain.port.RevokedTokenRepositoryPort;
import com.erp.auth.domain.port.UnitOfWork;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Instant;

/**
 * Periodic cleanup task for revoked access tokens.
 *
 * <p>Revocation records are only necessary while a token could otherwise be accepted.
 * Once a token reaches its natural expiration timestamp, verification fails anyway,
 * allowing expired revocation entries to be pruned to prevent table growth.
 */
@Component
public class RevokedTokenCleanupTask {

    private static final Logger log = LoggerFactory.getLogger(RevokedTokenCleanupTask.class);

    private final RevokedTokenRepositoryPort revokedTokenRepositoryPort;
    private final UnitOfWork unitOfWork;

    public RevokedTokenCleanupTask(RevokedTokenRepositoryPort revokedTokenRepositoryPort, UnitOfWork unitOfWork) {
        this.revokedTokenRepositoryPort = revokedTokenRepositoryPort;
        this.unitOfWork = unitOfWork;
    }

    @Scheduled(cron = "${erp.security.jwt.revoked-token-cleanup-cron:0 17 * * * *}")
    public void eliminarRevocacionesVencidas() {
        int eliminadas = unitOfWork.callInTransaction(
                () -> revokedTokenRepositoryPort.deleteExpired(Instant.now()));

        if (eliminadas > 0) {
            log.info("Se han eliminado {} revocaciones de tokens ya expirados", eliminadas);
        }
    }
}
