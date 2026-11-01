package com.erp.auth.application.dto.command;

import java.util.UUID;

public record UpdateUserPasswordCommand(UUID userId, String currentPassword, String newPassword) {
    public UpdateUserPasswordCommand {
        if (userId == null) {
            throw new IllegalArgumentException("User ID cannot be null");
        }
        if (currentPassword == null || currentPassword.isBlank()) {
            throw new IllegalArgumentException("Current password cannot be empty");
        }
        if (newPassword == null || newPassword.isBlank()) {
            throw new IllegalArgumentException("New password cannot be empty");
        }
    }
}
