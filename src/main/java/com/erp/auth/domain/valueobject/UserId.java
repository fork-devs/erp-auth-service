package com.erp.auth.domain.valueobject;

import java.io.Serializable;
import java.util.UUID;

/**
 * Value Object representing a unique user identifier.
 */
public record UserId(UUID value) implements Serializable {

    public UserId {
        if (value == null) {
            throw new IllegalArgumentException("UserId cannot be null");
        }
    }

    public static UserId of(UUID value) {
        return new UserId(value);
    }

    public static UserId fromString(String value) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException("UserId string cannot be blank");
        }
        return new UserId(UUID.fromString(value.trim()));
    }

    public static UserId generate() {
        return new UserId(UUID.randomUUID());
    }

    public UUID getValue() {
        return value;
    }

    @Override
    public String toString() {
        return value.toString();
    }
}
