package com.erp.auth.application.dto.result;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

public record UserResult(
        UUID id,
        UUID tenantId,
        String email,
        String fullName,
        boolean mfaEnabled,
        Set<String> roles,
        Instant createdAt
) {}
