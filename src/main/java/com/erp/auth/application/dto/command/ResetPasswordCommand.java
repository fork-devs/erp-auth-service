package com.erp.auth.application.dto.command;

import java.util.UUID;

public record ResetPasswordCommand(
        String token,
        String newPassword,
        UUID tenantId
) {}
