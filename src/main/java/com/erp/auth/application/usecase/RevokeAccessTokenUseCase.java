package com.erp.auth.application.usecase;

/**
 * Revocation of an access token.
 *
 * <p>Session termination cannot rely solely on refresh token revocation:
 * the access token accompanies every request and remains valid until its natural expiration
 * unless explicitly recorded as revoked.
 */
public interface RevokeAccessTokenUseCase {

    /**
     * Revokes the provided access token. An invalid or already expired token is treated
     * idempotently and does not cause an error.
     *
     * @param accessToken raw JWT access token to revoke
     */
    void revokeAccessToken(String accessToken);
}
