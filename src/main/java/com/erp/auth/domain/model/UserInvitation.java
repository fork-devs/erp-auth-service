package com.erp.auth.domain.model;

import com.erp.auth.domain.valueobject.Email;

import java.io.Serializable;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public class UserInvitation implements Serializable {

    private final UUID id;
    private final UUID tenantId;
    private final Email email;
    private final String fullName;
    private final RoleCode role;
    private final String tokenHash;
    private final Instant expiresAt;
    private Instant acceptedAt;
    private final Instant createdAt;

    public UserInvitation(UUID id,
                          UUID tenantId,
                          Email email,
                          String fullName,
                          RoleCode role,
                          String tokenHash,
                          Instant expiresAt,
                          Instant acceptedAt,
                          Instant createdAt) {
        if (id == null || tenantId == null || email == null || fullName == null || role == null || tokenHash == null || expiresAt == null) {
            throw new IllegalArgumentException("Campos obligatorios de UserInvitation no pueden ser nulos");
        }
        this.id = id;
        this.tenantId = tenantId;
        this.email = email;
        this.fullName = fullName.trim();
        this.role = role;
        this.tokenHash = tokenHash;
        this.expiresAt = expiresAt;
        this.acceptedAt = acceptedAt;
        this.createdAt = createdAt != null ? createdAt : Instant.now();
    }

    public static UserInvitation create(UUID tenantId,
                                        Email email,
                                        String fullName,
                                        RoleCode role,
                                        String tokenHash,
                                        Duration validity) {
        Instant now = Instant.now();
        return new UserInvitation(
                UUID.randomUUID(),
                tenantId,
                email,
                fullName,
                role,
                tokenHash,
                now.plus(validity),
                null,
                now
        );
    }

    public boolean isValid() {
        return acceptedAt == null && Instant.now().isBefore(expiresAt);
    }

    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }

    public boolean isAccepted() {
        return acceptedAt != null;
    }

    public void accept() {
        if (acceptedAt != null) {
            throw new IllegalStateException("La invitación ya ha sido aceptada previamente");
        }
        if (isExpired()) {
            throw new IllegalStateException("La invitación ha expirado");
        }
        this.acceptedAt = Instant.now();
    }

    public UUID getId() {
        return id;
    }

    public UUID getTenantId() {
        return tenantId;
    }

    public Email getEmail() {
        return email;
    }

    public String getFullName() {
        return fullName;
    }

    public RoleCode getRole() {
        return role;
    }

    public String getTokenHash() {
        return tokenHash;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public Instant getAcceptedAt() {
        return acceptedAt;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof UserInvitation that)) return false;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
