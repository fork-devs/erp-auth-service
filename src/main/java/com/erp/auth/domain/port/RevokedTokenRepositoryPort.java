package com.erp.auth.domain.port;

import com.erp.auth.domain.valueobject.TenantId;
import com.erp.auth.domain.valueobject.UserId;

import java.time.Instant;
import java.util.UUID;

/**
 * Registry of revoked access tokens.
 *
 * <p>Recording revocations allows true session termination:
 * the credential is rejected immediately, even if unexpired.
 *
 * <p>Entries are identified by the token's unique identifier ({@code jti}),
 * and scoped by user and tenant.
 */
public interface RevokedTokenRepositoryPort {

    /**
     * Records token revocation with full tenant and user scoping.
     */
    void revoke(UUID tokenId, UserId userId, TenantId tenantId, Instant expiresAt);

    /**
     * Legacy revocation method with fallback support during migration.
     */
    default void revoke(UUID tokenId, UUID userId, Instant expiresAt) {
        throw new UnsupportedOperationException("Multi-tenant safety: revoke requires TenantId");
    }

    /**
     * Checks whether the token has been revoked.
     */
    boolean isRevoked(UUID tokenId);

    /**
     * Purges entries whose tokens have already expired naturally.
     */
    int deleteExpired(Instant now);
}
