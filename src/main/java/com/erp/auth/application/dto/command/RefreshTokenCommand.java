package com.erp.auth.application.dto.command;

import java.util.UUID;

public record RefreshTokenCommand(
        String refreshToken,
        UUID tenantId
) {}
