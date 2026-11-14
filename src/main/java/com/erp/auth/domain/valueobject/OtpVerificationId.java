package com.erp.auth.domain.valueobject;

import java.io.Serializable;
import java.util.UUID;

public record OtpVerificationId(UUID value) implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final UUID NIL_UUID = new UUID(0L, 0L);

    public OtpVerificationId {
        if (value == null) {
            throw new IllegalArgumentException("OtpVerificationId cannot be null");
        }
        if (NIL_UUID.equals(value)) {
            throw new IllegalArgumentException("OtpVerificationId cannot be nil UUID (00000000-0000-0000-0000-000000000000)");
        }
    }

    public static OtpVerificationId fromString(String value) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException("OtpVerificationId string cannot be blank");
        }
        try {
            return new OtpVerificationId(UUID.fromString(value.trim()));
        } catch (IllegalArgumentException e) {
            if (e.getMessage() != null && e.getMessage().contains("nil UUID")) {
                throw e;
            }
            throw new IllegalArgumentException("Invalid OtpVerificationId format: " + value, e);
        }
    }

    public static OtpVerificationId generate() {
        return new OtpVerificationId(UUID.randomUUID());
    }

    @Override
    public String toString() {
        return value.toString();
    }
}
