package com.erp.auth.domain.valueobject;

import java.io.Serializable;

public record PasswordHash(String value) implements Serializable {

    public PasswordHash {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException("Password hash cannot be blank");
        }
    }

    public static PasswordHash of(String value) {
        return new PasswordHash(value);
    }

    public String getValue() {
        return value;
    }

    @Override
    public String toString() {
        return "********";
    }
}
