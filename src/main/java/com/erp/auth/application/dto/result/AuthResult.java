package com.erp.auth.application.dto.result;

import java.util.Set;
import java.util.UUID;

public record AuthResult(
        String accessToken,
        /**
         * Unique identifier of the access token matching its {@code jti} claim.
         * Required to selectively revoke this access token.
         */
        String accessTokenId,
        String refreshToken,
        String tokenType,
        long expiresInSeconds,
        UUID userId,
        UUID tenantId,
        String email,
        String fullName,
        Set<String> roles
) {}
