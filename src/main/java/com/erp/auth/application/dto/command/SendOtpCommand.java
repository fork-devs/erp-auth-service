package com.erp.auth.application.dto.command;

public record SendOtpCommand(String email) {
    public SendOtpCommand {
        if (email == null || email.isBlank()) {
            throw new IllegalArgumentException("Email cannot be empty");
        }
    }
}
