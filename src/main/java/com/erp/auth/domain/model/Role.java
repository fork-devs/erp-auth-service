package com.erp.auth.domain.model;

import java.io.Serializable;
import java.util.Objects;
import java.util.UUID;

public class Role implements Serializable {
    private final UUID id;
    private final RoleCode code;
    private final String description;

    public Role(UUID id, RoleCode code, String description) {
        if (id == null) {
            throw new IllegalArgumentException("Id del rol no puede ser nulo");
        }
        if (code == null) {
            throw new IllegalArgumentException("Código de rol no puede ser nulo");
        }
        this.id = id;
        this.code = code;
        this.description = description;
    }

    public static Role create(RoleCode code, String description) {
        return new Role(UUID.randomUUID(), code, description);
    }

    public UUID getId() {
        return id;
    }

    public RoleCode getCode() {
        return code;
    }

    public String getDescription() {
        return description;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Role role)) return false;
        return Objects.equals(code, role.code);
    }

    @Override
    public int hashCode() {
        return Objects.hash(code);
    }
}
