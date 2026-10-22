package com.erp.auth.domain.model;

import java.io.Serializable;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public class RefreshToken implements Serializable {
    private final UUID id;
    private final UUID userId;
    private final UUID tenantId;
    private final String tokenHash;
    private final Instant expiresAt;
    private boolean revoked;
    private final Instant createdAt;

    public RefreshToken(UUID id, UUID userId, UUID tenantId, String tokenHash, Instant expiresAt, boolean revoked, Instant createdAt) {
        if (id == null || userId == null || tenantId == null || tokenHash == null || expiresAt == null) {
            throw new IllegalArgumentException("Campos obligatorios del RefreshToken no pueden ser nulos");
        }
        this.id = id;
        this.userId = userId;
        this.tenantId = tenantId;
        this.tokenHash = tokenHash;
        this.expiresAt = expiresAt;
        this.revoked = revoked;
        this.createdAt = createdAt != null ? createdAt : Instant.now();
    }

    public static RefreshToken create(UUID userId, UUID tenantId, String tokenHash, Instant expiresAt) {
        return new RefreshToken(UUID.randomUUID(), userId, tenantId, tokenHash, expiresAt, false, Instant.now());
    }

    public boolean isValid() {
        return !revoked && Instant.now().isBefore(expiresAt);
    }

    public void revoke() {
        this.revoked = true;
    }

    public UUID getId() {
        return id;
    }

    public UUID getUserId() {
        return userId;
    }

    public UUID getTenantId() {
        return tenantId;
    }

    public String getTokenHash() {
        return tokenHash;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public boolean isRevoked() {
        return revoked;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof RefreshToken that)) return false;
        return Objects.equals(tokenHash, that.tokenHash);
    }

    @Override
    public int hashCode() {
        return Objects.hash(tokenHash);
    }
}
