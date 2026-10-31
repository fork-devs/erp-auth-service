package com.erp.auth.application.dto.command;

import java.util.UUID;

public record GoogleLoginCommand(String idToken, UUID tenantId) {
    public GoogleLoginCommand {
        if (idToken == null || idToken.isBlank()) {
            throw new IllegalArgumentException("Google ID token cannot be empty");
        }
    }
}
