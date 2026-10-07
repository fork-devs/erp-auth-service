package com.erp.auth.domain.model;

import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.domain.valueobject.PasswordHash;
import com.erp.auth.domain.valueobject.TenantId;

import java.io.Serializable;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

public class User implements Serializable {
    private final UUID id;
    private final TenantId tenantId;
    private final Email email;
    private PasswordHash passwordHash;
    private String fullName;
    private boolean mfaEnabled;
    private int failedAttempts;
    private Instant lockedUntil;
    private final Set<Role> roles;
    private final Instant createdAt;

    public User(UUID id,
                TenantId tenantId,
                Email email,
                PasswordHash passwordHash,
                String fullName,
                boolean mfaEnabled,
                int failedAttempts,
                Instant lockedUntil,
                Set<Role> roles,
                Instant createdAt) {
        if (id == null || tenantId == null || email == null || passwordHash == null) {
            throw new IllegalArgumentException("Campos obligatorios del usuario no pueden ser nulos");
        }
        this.id = id;
        this.tenantId = tenantId;
        this.email = email;
        this.passwordHash = passwordHash;
        this.fullName = fullName;
        this.mfaEnabled = mfaEnabled;
        this.failedAttempts = failedAttempts;
        this.lockedUntil = lockedUntil;
        this.roles = roles != null ? new HashSet<>(roles) : new HashSet<>();
        this.createdAt = createdAt != null ? createdAt : Instant.now();
    }

    public static User create(TenantId tenantId,
                              Email email,
                              PasswordHash passwordHash,
                              String fullName,
                              Set<Role> roles) {
        return new User(
                UUID.randomUUID(),
                tenantId,
                email,
                passwordHash,
                fullName,
                false,
                0,
                null,
                roles,
                Instant.now()
        );
    }

    public boolean isAccountLocked() {
        if (lockedUntil == null) {
            return false;
        }
        if (Instant.now().isAfter(lockedUntil)) {
            // El bloqueo ya expiró
            this.lockedUntil = null;
            this.failedAttempts = 0;
            return false;
        }
        return true;
    }

    public void recordFailedAttempt(int maxFailedAttempts, Duration lockDuration) {
        this.failedAttempts++;
        if (this.failedAttempts >= maxFailedAttempts) {
            this.lockedUntil = Instant.now().plus(lockDuration);
        }
    }

    public void recordSuccessfulLogin() {
        this.failedAttempts = 0;
        this.lockedUntil = null;
    }

    public void changePassword(PasswordHash newPasswordHash) {
        if (newPasswordHash == null) {
            throw new IllegalArgumentException("La nueva contraseña no puede ser nula");
        }
        this.passwordHash = newPasswordHash;
    }

    public void updateFullName(String fullName) {
        this.fullName = fullName;
    }

    public void addRole(Role role) {
        if (role != null) {
            this.roles.add(role);
        }
    }

    public void removeRole(RoleCode roleCode) {
        this.roles.removeIf(r -> r.getCode() == roleCode);
    }

    public boolean hasRole(RoleCode roleCode) {
        return roles.stream().anyMatch(r -> r.getCode() == roleCode);
    }

    public UUID getId() {
        return id;
    }

    public TenantId getTenantId() {
        return tenantId;
    }

    public Email getEmail() {
        return email;
    }

    public PasswordHash getPasswordHash() {
        return passwordHash;
    }

    public String getFullName() {
        return fullName;
    }

    public boolean isMfaEnabled() {
        return mfaEnabled;
    }

    public int getFailedAttempts() {
        return failedAttempts;
    }

    public Instant getLockedUntil() {
        return lockedUntil;
    }

    public Set<Role> getRoles() {
        return Collections.unmodifiableSet(roles);
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof User user)) return false;
        return Objects.equals(id, user.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
