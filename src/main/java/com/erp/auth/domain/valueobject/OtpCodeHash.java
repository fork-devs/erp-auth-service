package com.erp.auth.domain.valueobject;

import java.io.Serializable;
import java.util.Locale;
import java.util.regex.Pattern;

public record OtpCodeHash(String value) implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Pattern HEX_PATTERN = Pattern.compile("^[a-fA-F0-9]{32,128}$");

    public OtpCodeHash {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException("OTP code hash cannot be null or blank");
        }
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        if (!HEX_PATTERN.matcher(normalized).matches()) {
            throw new IllegalArgumentException("OTP code hash must be a valid hexadecimal string of 32 to 128 characters");
        }
        value = normalized;
    }

    public static OtpCodeHash of(String value) {
        return new OtpCodeHash(value);
    }

    @Override
    public String toString() {
        return "********";
    }
}
