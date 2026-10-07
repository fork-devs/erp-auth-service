package com.erp.auth.application.dto.command;

public record ResetPasswordCommand(
        String token,
        String newPassword
) {}
