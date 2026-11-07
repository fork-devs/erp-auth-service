package com.erp.auth.domain.port;

import com.erp.auth.domain.model.RefreshToken;
import com.erp.auth.domain.model.TokenHash;
import com.erp.auth.domain.valueobject.TenantId;
import com.erp.auth.domain.valueobject.UserId;

import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepositoryPort {

    RefreshToken save(RefreshToken refreshToken);

    Optional<RefreshToken> findByTokenHash(TokenHash tokenHash);

    Optional<RefreshToken> findByTokenHashAndTenantId(TokenHash tokenHash, TenantId tenantId);

    void revokeByTokenHash(TokenHash tokenHash);

    void revokeAllByUserId(UserId userId, TenantId tenantId);

    // Backward compatibility overloads for smooth phased migration
    default Optional<RefreshToken> findByTokenHash(String tokenHash) {
        return findByTokenHash(TokenHash.of(tokenHash));
    }

    default Optional<RefreshToken> findByTokenHashAndTenantId(String tokenHash, UUID tenantId) {
        return findByTokenHashAndTenantId(TokenHash.of(tokenHash), TenantId.fromString(tenantId.toString()));
    }

    default void revokeByTokenHash(String tokenHash) {
        revokeByTokenHash(TokenHash.of(tokenHash));
    }

    default void revokeAllByUserId(UUID userId, UUID tenantId) {
        revokeAllByUserId(new UserId(userId), TenantId.fromString(tenantId.toString()));
    }

    default void revokeAllByUserId(UUID userId) {
        throw new UnsupportedOperationException("Multi-tenant safety: revokeAllByUserId requires TenantId");
    }
}
