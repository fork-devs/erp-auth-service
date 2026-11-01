package com.erp.auth.interfaces.rest.dto.response;

import com.erp.auth.domain.model.RoleCode;

import java.time.Instant;
import java.util.UUID;

public record InvitationDetailsResponse(
        UUID id,
        UUID tenantId,
        String email,
        String fullName,
        RoleCode role,
        boolean valid,
        Instant expiresAt
) {}
