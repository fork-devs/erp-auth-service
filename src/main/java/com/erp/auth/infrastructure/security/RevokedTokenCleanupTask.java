package com.erp.auth.infrastructure.security;

import com.erp.auth.domain.port.RevokedTokenRepositoryPort;
import com.erp.auth.domain.port.UnitOfWork;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Instant;

/**
 * Limpieza del registro de tokens revocados.
 *
 * <p>Una revocacion solo tiene sentido mientras el token podria aceptarse.
 * Una vez que el token ha expirado, su entrada ya no sirve para nada: la
 * verificacion lo rechazara por expiracion. Conservarlas seria una tabla que
 * crece sin limite.
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
