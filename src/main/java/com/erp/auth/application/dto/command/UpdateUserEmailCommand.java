package com.erp.auth.application.dto.command;

import java.util.UUID;

public record UpdateUserEmailCommand(UUID userId, String newEmail) {
    public UpdateUserEmailCommand {
        if (userId == null) {
            throw new IllegalArgumentException("User ID cannot be null");
        }
        if (newEmail == null || newEmail.isBlank()) {
            throw new IllegalArgumentException("New email cannot be empty");
        }
    }
}
