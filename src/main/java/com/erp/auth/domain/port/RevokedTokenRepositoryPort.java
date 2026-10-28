package com.erp.auth.domain.port;

import java.time.Instant;
import java.util.UUID;

/**
 * Registry of revoked access tokens.
 *
 * <p>An access token is otherwise only invalidated upon reaching its expiration time
 * (a 15-minute window). Recording revocations allows true session termination:
 * the credential is rejected immediately, even if unexpired.
 *
 * <p>Entries are identified by the token's unique identifier ({@code jti}),
 * which is globally unique.
 */
public interface RevokedTokenRepositoryPort {

    /**
     * Records token revocation. Revoking the same token multiple times is idempotent.
     */
    void revoke(UUID tokenId, UUID userId, Instant expiresAt);

    /**
     * Checks whether the token has been revoked.
     */
    boolean isRevoked(UUID tokenId);

    /**
     * Purges entries whose tokens have already expired naturally.
     *
     * @param now current timestamp
     * @return the number of purged entries
     */
    int deleteExpired(Instant now);
}
