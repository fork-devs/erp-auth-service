package com.erp.auth.interfaces.rest.dto.response;

import com.erp.auth.domain.model.RoleCode;

import java.time.Instant;
import java.util.UUID;

public record InviteUserResponse(
        UUID id,
        UUID tenantId,
        String email,
        String fullName,
        RoleCode role,
        Instant expiresAt,
        String invitationUrl
) {}
