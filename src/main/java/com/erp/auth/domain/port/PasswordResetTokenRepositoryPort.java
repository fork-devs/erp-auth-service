package com.erp.auth.domain.port;

import com.erp.auth.domain.model.PasswordResetToken;
import com.erp.auth.domain.model.TokenHash;
import com.erp.auth.domain.valueobject.TenantId;
import com.erp.auth.domain.valueobject.UserId;

import java.util.Optional;
import java.util.UUID;

public interface PasswordResetTokenRepositoryPort {

    PasswordResetToken save(PasswordResetToken token);

    Optional<PasswordResetToken> findByTokenHash(TokenHash tokenHash);

    Optional<PasswordResetToken> findByTokenHashAndTenantId(TokenHash tokenHash, TenantId tenantId);

    void invalidateAllByUserId(UserId userId, TenantId tenantId);

    // Backward compatibility overloads for smooth phased migration
    default Optional<PasswordResetToken> findByTokenHash(String tokenHash) {
        return findByTokenHash(TokenHash.of(tokenHash));
    }

    default Optional<PasswordResetToken> findByTokenHashAndTenantId(String tokenHash, UUID tenantId) {
        return findByTokenHashAndTenantId(TokenHash.of(tokenHash), TenantId.fromString(tenantId.toString()));
    }

    default void invalidateAllByUserId(UUID userId, UUID tenantId) {
        invalidateAllByUserId(new UserId(userId), TenantId.fromString(tenantId.toString()));
    }

    default void invalidateAllByUserId(UUID userId) {
        throw new UnsupportedOperationException("Multi-tenant safety: invalidateAllByUserId requires TenantId");
    }
}
