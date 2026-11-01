package com.erp.auth.application.dto.command;

import com.erp.auth.domain.model.RoleCode;

import java.util.UUID;

public record InviteUserCommand(
        UUID tenantId,
        String email,
        String fullName,
        RoleCode role,
        RoleCode actorRole
) {}
