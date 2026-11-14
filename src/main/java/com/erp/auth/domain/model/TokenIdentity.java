package com.erp.auth.domain.model;

import com.erp.auth.domain.valueobject.TenantId;

import java.time.Instant;
import java.util.UUID;

/**
 * Identity of an access token.
 *
 * <p>Represents the data required to revoke it: its unique identifier (the key
 * in the revocation registry), its owner, tenant, and its expiration timestamp, which
 * allows cleaning up the registry once the token has naturally expired.
 */
public record TokenIdentity(
        UUID tokenId,
        UUID userId,
        TenantId tenantId,
        Instant expiresAt
) {
    public TokenIdentity(UUID tokenId, UUID userId, Instant expiresAt) {
        this(tokenId, userId, null, expiresAt);
    }
}
