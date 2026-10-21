package com.erp.auth.infrastructure.persistence.entity;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Entity
@Table(name = "users")
public class UserJpaEntity {

    @Id
    private UUID id;

    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    @Column(nullable = false, unique = true, length = 255)
    private String email;

    @Column(name = "password_hash", nullable = false, length = 255)
    private String passwordHash;

    @Column(name = "full_name", length = 255)
    private String fullName;

    @Column(name = "mfa_enabled")
    private Boolean mfaEnabled;

    @Column(name = "failed_attempts")
    private Integer failedAttempts;

    @Column(name = "locked_until")
    private Instant lockedUntil;

    @Column(name = "created_at")
    private Instant createdAt;

    /**
     * Asignaciones de rol del usuario.
     *
     * <p>La tabla user_roles tiene clave primaria compuesta (user_id, role_id,
     * tenant_id), de modo que no puede representarse con una @ManyToMany: su
     * @JoinTable solo admite dos claves foraneas y la columna tenant_id nunca
     * se escribia. Se declara como una coleccion de la entidad de asignacion.
     *
     * <p>La columna user_id no se escribe desde aqui porque forma parte de la
     * clave embebida de UserRoleJpaEntity: Hibernate escribirla dos veces
     * produciria un INSERT con la misma columna duplicada.
     */
    @OneToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER)
    @JoinColumn(name = "user_id", insertable = false, updatable = false)
    private Set<UserRoleJpaEntity> userRoles = new HashSet<>();

    public UserJpaEntity() {}

    public UserJpaEntity(UUID id, UUID tenantId, String email, String passwordHash, String fullName, Boolean mfaEnabled, Integer failedAttempts, Instant lockedUntil, Instant createdAt, Set<UserRoleJpaEntity> userRoles) {
        this.id = id;
        this.tenantId = tenantId;
        this.email = email;
        this.passwordHash = passwordHash;
        this.fullName = fullName;
        this.mfaEnabled = mfaEnabled;
        this.failedAttempts = failedAttempts;
        this.lockedUntil = lockedUntil;
        this.createdAt = createdAt;
        this.userRoles = userRoles != null ? userRoles : new HashSet<>();
    }

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public UUID getTenantId() {
        return tenantId;
    }

    public void setTenantId(UUID tenantId) {
        this.tenantId = tenantId;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    public String getFullName() {
        return fullName;
    }

    public void setFullName(String fullName) {
        this.fullName = fullName;
    }

    public Boolean getMfaEnabled() {
        return mfaEnabled;
    }

    public void setMfaEnabled(Boolean mfaEnabled) {
        this.mfaEnabled = mfaEnabled;
    }

    public Integer getFailedAttempts() {
        return failedAttempts;
    }

    public void setFailedAttempts(Integer failedAttempts) {
        this.failedAttempts = failedAttempts;
    }

    public Instant getLockedUntil() {
        return lockedUntil;
    }

    public void setLockedUntil(Instant lockedUntil) {
        this.lockedUntil = lockedUntil;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public Set<UserRoleJpaEntity> getUserRoles() {
        return userRoles;
    }

    public void setUserRoles(Set<UserRoleJpaEntity> userRoles) {
        this.userRoles = userRoles;
    }
}
