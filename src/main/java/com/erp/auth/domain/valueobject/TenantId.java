package com.erp.auth.domain.valueobject;

import java.io.Serializable;
import java.util.Objects;
import java.util.UUID;

public final class TenantId implements Serializable {
    private final UUID value;

    public TenantId(UUID value) {
        if (value == null) {
            throw new IllegalArgumentException("TenantId no puede ser nulo");
        }
        this.value = value;
    }

    public static TenantId fromString(String value) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException("TenantId string no puede estar vacío");
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
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof TenantId tenantId)) return false;
        return Objects.equals(value, tenantId.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    @Override
    public String toString() {
        return value.toString();
    }
}
