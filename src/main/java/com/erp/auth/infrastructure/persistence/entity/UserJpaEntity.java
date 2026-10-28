package com.erp.auth.infrastructure.persistence.entity;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import jakarta.persistence.Version;

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

    /**
     * Email is unique per tenant, not globally: uniqueness is defined by the composite
     * key (tenant_id, email), enforced by Flyway migration V10.
     *
     * <p>With global uniqueness, a workshop could not register an employee using an email
     * already registered in another workshop, and unique constraint violations leaked
     * user enumeration across tenants.
     */
    @Column(nullable = false, length = 255)
    private String email;

    @Column(name = "password_hash", nullable = false, length = 255)
    private String passwordHash;

    @Column(name = "full_name", length = 255)
    private String fullName;

    @Column(name = "mfa_enabled")
    private Boolean mfaEnabled;

    /**
     * Optimistic locking version. Prevents concurrent writes from overwriting each other
     * without detection.
     */
    @Version
    @Column(name = "version", nullable = false)
    private Long version;

    /**
     * Encrypted second-factor secret. Plaintext is never stored in persistence to
     * prevent unauthorized TOTP generation from database dumps.
     */
    @Column(name = "mfa_secret_ciphertext")
    private String mfaSecretCiphertext;

    /**
     * Time-step counter of the last accepted TOTP code. Prevents replay attacks
     * within the validity window.
     */
    @Column(name = "mfa_last_code_counter")
    private Long mfaLastCodeCounter;

    @Column(name = "failed_attempts")
    private Integer failedAttempts;

    @Column(name = "locked_until")
    private Instant lockedUntil;

    @Column(name = "created_at")
    private Instant createdAt;

    /**
     * Role assignments for the user.
     *
     * <p>The {@code user_roles} table uses a composite primary key (user_id, role_id, tenant_id),
     * which cannot be mapped via simple {@code @ManyToMany} because {@code @JoinTable} cannot
     * populate the additional {@code tenant_id} column required by multi-tenant RLS.
     *
     * <p>The {@code user_id} column is marked read-only on this mapping because it is already
     * managed by the embedded identifier in {@link UserRoleJpaEntity}.
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

    public String getMfaSecretCiphertext() {
        return mfaSecretCiphertext;
    }

    public void setMfaSecretCiphertext(String mfaSecretCiphertext) {
        this.mfaSecretCiphertext = mfaSecretCiphertext;
    }

    public Long getVersion() {
        return version;
    }

    public void setVersion(Long version) {
        this.version = version;
    }

    public Long getMfaLastCodeCounter() {
        return mfaLastCodeCounter;
    }

    public void setMfaLastCodeCounter(Long mfaLastCodeCounter) {
        this.mfaLastCodeCounter = mfaLastCodeCounter;
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
