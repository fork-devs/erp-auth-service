package com.erp.auth.application.dto.command;

public record VerifyOtpCommand(String email, String code) {
    public VerifyOtpCommand {
        if (email == null || email.isBlank()) {
            throw new IllegalArgumentException("Email cannot be empty");
        }
        if (code == null || code.isBlank()) {
            throw new IllegalArgumentException("OTP code cannot be empty");
        }
    }
}
