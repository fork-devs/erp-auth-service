package com.erp.auth.application.dto.result;

import com.erp.auth.domain.model.RoleCode;

import java.time.Instant;
import java.util.UUID;

public record InvitationDetailsResult(
        UUID id,
        UUID tenantId,
        String email,
        String fullName,
        RoleCode role,
        boolean valid,
        Instant expiresAt
) {}
