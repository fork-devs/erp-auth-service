package com.erp.auth.domain.valueobject;

import java.io.Serializable;
import java.util.Objects;

public final class PasswordHash implements Serializable {
    private final String value;

    public PasswordHash(String value) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException("El hash de contraseña no puede estar vacío");
        }
        this.value = value;
    }

    public static PasswordHash of(String value) {
        return new PasswordHash(value);
    }

    public String getValue() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof PasswordHash that)) return false;
        return Objects.equals(value, that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    @Override
    public String toString() {
        return "********";
    }
}
