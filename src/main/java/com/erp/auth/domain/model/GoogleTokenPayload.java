package com.erp.auth.domain.model;

public record GoogleTokenPayload(
        String email,
        String fullName,
        String subject
) {
    public GoogleTokenPayload {
        if (email == null || email.isBlank()) {
            throw new IllegalArgumentException("Google token email cannot be empty");
        }
    }
}
