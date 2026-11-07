package com.erp.auth.domain.model;

import java.io.Serializable;
import java.util.regex.Pattern;

/**
 * Value Object representing a cryptographic token hash (e.g. HMAC-SHA256 or SHA-256).
 * Enforces non-null, non-blank and valid hexadecimal format.
 */
public record TokenHash(String value) implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Pattern HEX_PATTERN = Pattern.compile("^[a-fA-F0-9]{32,128}$");

    public TokenHash {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException("Token hash cannot be blank");
        }
        String trimmed = value.trim();
        if (!HEX_PATTERN.matcher(trimmed).matches()) {
            throw new IllegalArgumentException("Token hash must be a valid hexadecimal string of 32 to 128 characters");
        }
        value = trimmed.toLowerCase();
    }

    public static TokenHash of(String value) {
        return new TokenHash(value);
    }

    @Override
    public String toString() {
        return value;
    }
}
