package com.erp.auth.infrastructure.persistence.adapter;

import com.erp.auth.domain.port.RevokedTokenRepositoryPort;
import com.erp.auth.domain.valueobject.TenantId;
import com.erp.auth.domain.valueobject.UserId;
import com.erp.auth.infrastructure.persistence.entity.RevokedTokenJpaEntity;
import com.erp.auth.infrastructure.persistence.repository.SpringDataRevokedTokenRepository;
import com.erp.auth.infrastructure.persistence.TransactionGuard;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class RevokedTokenPersistenceAdapter implements RevokedTokenRepositoryPort {

    private final TransactionGuard transactionGuard;
    private final SpringDataRevokedTokenRepository repository;
    private final Map<UUID, Instant> fastTtlStore = new ConcurrentHashMap<>();

    public RevokedTokenPersistenceAdapter(SpringDataRevokedTokenRepository repository,
                                          TransactionGuard transactionGuard) {
        this.repository = repository;
        this.transactionGuard = transactionGuard;
    }

    @Override
    @Transactional(propagation = Propagation.MANDATORY)
    public void revoke(UUID tokenId, UserId userId, TenantId tenantId, Instant expiresAt) {
        transactionGuard.requireActiveTransaction("revokeToken");
        if (tokenId == null) {
            throw new IllegalArgumentException("TokenId (jti) cannot be null");
        }
        if (userId == null) {
            throw new IllegalArgumentException("UserId cannot be null");
        }
        if (tenantId == null) {
            throw new IllegalArgumentException("TenantId cannot be null");
        }
        if (expiresAt == null) {
            throw new IllegalArgumentException("Expiration instant cannot be null");
        }

        // Fast TTL cache update for hot-path immediate visibility
        fastTtlStore.put(tokenId, expiresAt);

        // Idempotent persistent storage
        if (repository.existsById(tokenId)) {
            return;
        }
        repository.save(new RevokedTokenJpaEntity(tokenId, userId.value(), tenantId.value(), expiresAt, Instant.now()));
    }

    @Override
    public void revoke(UUID tokenId, UUID userId, Instant expiresAt) {
        throw new UnsupportedOperationException("Multi-tenant safety: revoke requires UserId and TenantId Value Objects");
    }

    @Override
    @Transactional(readOnly = true)
    public boolean isRevoked(UUID tokenId) {
        if (tokenId == null) {
            return false;
        }

        // 1. Fast in-memory TTL lookup
        Instant expiresAt = fastTtlStore.get(tokenId);
        if (expiresAt != null) {
            if (expiresAt.isAfter(Instant.now())) {
                return true;
            }
            fastTtlStore.remove(tokenId);
            return false;
        }

        // 2. Persistent store lookup with warm-up
        boolean exists = repository.existsById(tokenId);
        if (exists) {
            fastTtlStore.put(tokenId, Instant.now().plus(Duration.ofMinutes(15)));
        }
        return exists;
    }

    @Override
    @Transactional(propagation = Propagation.MANDATORY)
    public int deleteExpired(Instant now) {
        transactionGuard.requireActiveTransaction("deleteExpiredRevokedTokens");
        fastTtlStore.entrySet().removeIf(entry -> entry.getValue().isBefore(now));
        return repository.deleteExpired(now);
    }
}
