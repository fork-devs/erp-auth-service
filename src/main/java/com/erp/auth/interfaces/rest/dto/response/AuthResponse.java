package com.erp.auth.interfaces.rest.dto.response;

import java.util.Set;
import java.util.UUID;

public record AuthResponse(
        String accessToken,
        /**
         * Identificador unico del token de acceso, tal como va en su claim
         * {@code jti}. Es lo que hay que presentar para revocar ese token.
         */
        String accessTokenId,
        String refreshToken,
        String tokenType,
        long expiresIn,
        UUID userId,
        UUID tenantId,
        String email,
        String fullName,
        Set<String> roles
) {}
