package com.erp.auth.domain.model;

import java.time.Instant;
import java.util.UUID;

/**
 * Identity of an access token.
 *
 * <p>Represents the data required to revoke it: its unique identifier (the key
 * in the revocation registry), its owner, and its expiration timestamp, which
 * allows cleaning up the registry once the token has naturally expired.
 */
public record TokenIdentity(
        UUID tokenId,
        UUID userId,
        Instant expiresAt
) {
}
