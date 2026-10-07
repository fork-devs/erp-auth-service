package com.erp.auth.application.dto.result;

import java.util.Set;
import java.util.UUID;

public record AuthResult(
        String accessToken,
        String refreshToken,
        String tokenType,
        long expiresInSeconds,
        UUID userId,
        UUID tenantId,
        String email,
        String fullName,
        Set<String> roles
) {}
