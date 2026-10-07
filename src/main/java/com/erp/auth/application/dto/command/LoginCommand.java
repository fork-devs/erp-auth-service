package com.erp.auth.application.dto.command;

import java.util.UUID;

public record LoginCommand(
        String email,
        String password,
        UUID tenantId
) {}
