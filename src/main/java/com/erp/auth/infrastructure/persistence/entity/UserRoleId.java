package com.erp.auth.infrastructure.persistence.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;

import java.io.Serializable;
import java.util.Objects;
import java.util.UUID;

/**
 * Identidad de una asignacion de rol: (user_id, role_id, tenant_id).
 *
 * <p>La tabla {@code user_roles} tiene clave primaria compuesta por las tres
 * columnas, de modo que no puede representarse con una clave simple. Se
 * declara como clave embebida y no como clase de identificadores porque las
 * columnas son valores simples y no asociaciones.
 */
@Embeddable
public class UserRoleId implements Serializable {

    @Column(name = "user_id", nullable = false)
    private UUID userId;

    @Column(name = "role_id", nullable = false)
    private UUID roleId;

    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    public UserRoleId() {
    }

    public UserRoleId(UUID userId, UUID roleId, UUID tenantId) {
        this.userId = userId;
        this.roleId = roleId;
        this.tenantId = tenantId;
    }

    public UUID getUserId() {
        return userId;
    }

    public UUID getRoleId() {
        return roleId;
    }

    public UUID getTenantId() {
        return tenantId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof UserRoleId that)) return false;
        return Objects.equals(userId, that.userId)
                && Objects.equals(roleId, that.roleId)
                && Objects.equals(tenantId, that.tenantId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(userId, roleId, tenantId);
    }

    @Override
    public String toString() {
        return "UserRoleId{userId=" + userId + ", roleId=" + roleId + ", tenantId=" + tenantId + '}';
    }
}
