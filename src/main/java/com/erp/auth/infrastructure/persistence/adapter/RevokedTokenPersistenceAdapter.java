package com.erp.auth.infrastructure.persistence.adapter;

import com.erp.auth.domain.port.RevokedTokenRepositoryPort;
import com.erp.auth.infrastructure.persistence.entity.RevokedTokenJpaEntity;
import com.erp.auth.infrastructure.persistence.repository.SpringDataRevokedTokenRepository;
import com.erp.auth.infrastructure.persistence.TransactionGuard;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

@Component
public class RevokedTokenPersistenceAdapter implements RevokedTokenRepositoryPort {

    private final TransactionGuard transactionGuard;
    private final SpringDataRevokedTokenRepository repository;

    public RevokedTokenPersistenceAdapter(SpringDataRevokedTokenRepository repository,
                                          TransactionGuard transactionGuard) {
        this.repository = repository;
        this.transactionGuard = transactionGuard;
    }

    @Override
    public void revoke(UUID tokenId, UUID userId, Instant expiresAt) {
        transactionGuard.requireActiveTransaction("revokeToken");
        if (repository.existsById(tokenId)) {
            // La revocacion es idempotente: cerrar la sesion dos veces no
            // puede fallar.
            return;
        }
        repository.save(new RevokedTokenJpaEntity(tokenId, userId, expiresAt, Instant.now()));
    }

    @Override
    @Transactional(readOnly = true)
    public boolean isRevoked(UUID tokenId) {
        return repository.existsById(tokenId);
    }

    @Override
    public int deleteExpired(Instant now) {
        transactionGuard.requireActiveTransaction("deleteExpiredRevokedTokens");
        return repository.deleteExpired(now);
    }
}
