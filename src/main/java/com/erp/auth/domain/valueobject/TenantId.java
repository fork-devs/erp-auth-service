package com.erp.auth.domain.valueobject;

import java.io.Serializable;
import java.util.UUID;

public record TenantId(UUID value) implements Serializable {

    public TenantId {
        if (value == null) {
            throw new IllegalArgumentException("TenantId cannot be null");
        }
    }

    public static TenantId fromString(String value) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException("TenantId string cannot be blank");
        }
        return new TenantId(UUID.fromString(value.trim()));
    }

    public static TenantId generate() {
        return new TenantId(UUID.randomUUID());
    }

    public UUID getValue() {
        return value;
    }

    @Override
    public String toString() {
        return value.toString();
    }
}
