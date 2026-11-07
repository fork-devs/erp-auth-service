package com.erp.auth.domain.valueobject;

import java.io.Serializable;
import java.util.UUID;

public record TenantId(UUID value) implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final UUID NIL_UUID = new UUID(0L, 0L);

    public TenantId {
        if (value == null) {
            throw new IllegalArgumentException("TenantId cannot be null");
        }
        if (NIL_UUID.equals(value)) {
            throw new IllegalArgumentException("TenantId cannot be nil UUID (00000000-0000-0000-0000-000000000000)");
        }
    }

    public static TenantId fromString(String value) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException("TenantId string cannot be blank");
        }
        try {
            return new TenantId(UUID.fromString(value.trim()));
        } catch (IllegalArgumentException e) {
            if (e.getMessage() != null && e.getMessage().contains("nil UUID")) {
                throw e;
            }
            throw new IllegalArgumentException("Invalid TenantId format: " + value, e);
        }
    }

    public static TenantId generate() {
        return new TenantId(UUID.randomUUID());
    }

    @Override
    public String toString() {
        return value.toString();
    }
}
