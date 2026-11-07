package com.erp.auth.domain.port;

import com.erp.auth.domain.model.TokenHash;
import com.erp.auth.domain.model.TokenIdentity;
import com.erp.auth.domain.model.User;
import com.erp.auth.domain.valueobject.UserId;

import java.time.Duration;
import java.util.Map;
import java.util.UUID;

/**
 * Credential token issuance and claims management.
 *
 * <p>All token types issued by the service share standard claims: issuer,
 * **audience**, **unique identifier** ({@code jti}), issued-at time, and expiration time.
 * The unique identifier enables granular revocation of individual tokens, and the audience
 * guarantees that a token issued for this service cannot be accepted elsewhere.
 */
public interface TokenSignerPort {

    /**
     * Issues an access token containing subject, tenant, and assigned roles.
     */
    String generateAccessToken(User user);

    /**
     * Issues a refresh token containing subject and tenant.
     */
    String generateRefreshToken(User user);

    /**
     * Issues a password reset token linked to the given user ID.
     */
    String generatePasswordResetToken(UserId userId);

    default String generatePasswordResetToken(UUID userId) {
        return generatePasswordResetToken(UserId.of(userId));
    }

    String hashToken(String rawToken);

    default TokenHash hashTokenToVO(String rawToken) {
        return TokenHash.of(hashToken(rawToken));
    }

    /**
     * Extracts the unique token identifier matching the {@code jti} claim, used to record
     * revocation in the registry.
     */
    String extractTokenId(String token);

    /**
     * Extracts the token identity (unique ID, subject, and expiration) needed for revocation.
     */
    TokenIdentity extractIdentity(String token);

    Duration getAccessTokenDuration();

    Duration getRefreshTokenDuration();

    Duration getPasswordResetTokenDuration();

    Map<String, Object> getJwksPublicKeySet();

    /**
     * Returns the intended audience for issued tokens, verified by resource servers.
     */
    String getAudience();
}
