package com.erp.auth.interfaces.rest.dto.response;

import java.util.Set;
import java.util.UUID;

public record AuthResponse(
        String accessToken,
        String refreshToken,
        String tokenType,
        long expiresIn,
        UUID userId,
        UUID tenantId,
        String email,
        String fullName,
        Set<String> roles
) {}
