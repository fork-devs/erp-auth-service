package com.erp.auth.domain.valueobject;

import java.io.Serializable;
import java.util.UUID;

/**
 * Value Object representing a unique user identifier.
 */
public record UserId(UUID value) implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final UUID NIL_UUID = new UUID(0L, 0L);

    public UserId {
        if (value == null) {
            throw new IllegalArgumentException("UserId cannot be null");
        }
        if (NIL_UUID.equals(value)) {
            throw new IllegalArgumentException("UserId cannot be nil UUID (00000000-0000-0000-0000-000000000000)");
        }
    }

    public static UserId fromString(String value) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException("UserId string cannot be blank");
        }
        try {
            return new UserId(UUID.fromString(value.trim()));
        } catch (IllegalArgumentException e) {
            if (e.getMessage() != null && e.getMessage().contains("nil UUID")) {
                throw e;
            }
            throw new IllegalArgumentException("Invalid UserId format: " + value, e);
        }
    }

    public static UserId generate() {
        return new UserId(UUID.randomUUID());
    }

    @Override
    public String toString() {
        return value.toString();
    }
}
