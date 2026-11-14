package com.erp.auth.domain.model;

import com.erp.auth.domain.valueobject.TenantId;
import com.erp.auth.domain.valueobject.UserId;

import java.io.Serializable;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public class RefreshToken implements Serializable {
    private final UUID id;
    private final UserId userId;
    private final TenantId tenantId;
    private final TokenHash tokenHash;
    private final Instant expiresAt;
    private boolean revoked;
    private final Instant createdAt;

    public RefreshToken(UUID id, UserId userId, TenantId tenantId, TokenHash tokenHash, Instant expiresAt, boolean revoked, Instant createdAt) {
        if (id == null || userId == null || tenantId == null || tokenHash == null || expiresAt == null) {
            throw new IllegalArgumentException("Required RefreshToken fields cannot be null");
        }
        this.id = id;
        this.userId = userId;
        this.tenantId = tenantId;
        this.tokenHash = tokenHash;
        this.expiresAt = expiresAt;
        this.revoked = revoked;
        this.createdAt = createdAt != null ? createdAt : Instant.now();
    }

    public RefreshToken(UUID id, UUID userId, UUID tenantId, String tokenHash, Instant expiresAt, boolean revoked, Instant createdAt) {
        this(id,
             userId != null ? new UserId(userId) : null,
             tenantId != null ? TenantId.fromString(tenantId.toString()) : null,
             tokenHash != null ? TokenHash.of(tokenHash) : null,
             expiresAt,
             revoked,
             createdAt);
    }

    public static RefreshToken create(UserId userId, TenantId tenantId, TokenHash tokenHash, Instant expiresAt) {
        return new RefreshToken(UUID.randomUUID(), userId, tenantId, tokenHash, expiresAt, false, Instant.now());
    }

    public static RefreshToken create(UUID userId, UUID tenantId, String tokenHash, Instant expiresAt) {
        return create(new UserId(userId), TenantId.fromString(tenantId.toString()), TokenHash.of(tokenHash), expiresAt);
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

    public UserId getUserIdVO() {
        return userId;
    }

    public UUID getUserId() {
        return userId.value();
    }

    public TenantId getTenantIdVO() {
        return tenantId;
    }

    public UUID getTenantId() {
        return tenantId.value();
    }

    public TokenHash getTokenHashVO() {
        return tokenHash;
    }

    public String getTokenHash() {
        return tokenHash.value();
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
