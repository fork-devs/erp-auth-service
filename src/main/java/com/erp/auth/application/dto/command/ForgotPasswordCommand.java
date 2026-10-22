package com.erp.auth.application.dto.command;

import java.util.UUID;

public record ForgotPasswordCommand(
        String email,
        UUID tenantId
) {}
