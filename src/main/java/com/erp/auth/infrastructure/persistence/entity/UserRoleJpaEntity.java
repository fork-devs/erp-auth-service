package com.erp.auth.infrastructure.persistence.entity;

import jakarta.persistence.Column;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

import java.time.Instant;

/**
 * Represents the assignment of a role to a user within a specific tenant workshop.
 *
 * <p>The {@code user_roles} table has a composite primary key (user_id, role_id, tenant_id).
 * It cannot be represented as a standard Hibernate {@code @ManyToMany} mapping because
 * {@code @JoinTable} does not populate the tenant foreign key column required by the schema
 * and RLS policies. See docs/doc-estado-implementacion.md, finding P0 5.5.
 *
 * <p>Explicit entity mapping with {@link UserRoleId} ensures all columns are correctly persisted.
 */
@Entity
@Table(name = "user_roles")
public class UserRoleJpaEntity {

    @EmbeddedId
    private UserRoleId id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "role_id", insertable = false, updatable = false)
    private RoleJpaEntity role;

    @Column(name = "created_at", insertable = false, updatable = false)
    private Instant createdAt;

    public UserRoleJpaEntity() {
    }

    public UserRoleJpaEntity(UserRoleId id, RoleJpaEntity role) {
        this.id = id;
        this.role = role;
    }

    public UserRoleId getId() {
        return id;
    }

    public void setId(UserRoleId id) {
        this.id = id;
    }

    public RoleJpaEntity getRole() {
        return role;
    }

    public void setRole(RoleJpaEntity role) {
        this.role = role;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }
}
