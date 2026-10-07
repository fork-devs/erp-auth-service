package com.erp.auth.interfaces.rest.dto.response;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

public record UserResponse(
        UUID id,
        UUID tenantId,
        String email,
        String fullName,
        boolean mfaEnabled,
        Set<String> roles,
        Instant createdAt
) {}
