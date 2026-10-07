package com.erp.auth.application.dto.command;

import java.util.Set;
import java.util.UUID;

public record RegisterUserCommand(
        UUID tenantId,
        String email,
        String password,
        String fullName,
        Set<String> roleCodes
) {}
