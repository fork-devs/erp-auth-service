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
 * Asignacion de un rol a un usuario dentro de un taller.
 *
 * <p>La tabla {@code user_roles} tiene clave primaria compuesta
 * (user_id, role_id, tenant_id). No puede representarse con una
 * {@code @ManyToMany} de Hibernate: el {@code @JoinTable} solo admite las dos
 * claves foraneas de la asociacion, de modo que la columna {@code tenant_id}
 * nunca se escribia y el INSERT fallaba contra su restriccion NOT NULL.
 * Ver docs/doc-estado-implementacion.md, hallazgo P0 5.5.
 *
 * <p>Por eso la tabla se declara como entidad propia, con su clave embebida.
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
