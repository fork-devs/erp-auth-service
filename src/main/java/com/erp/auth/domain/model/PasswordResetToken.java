package com.erp.auth.domain.model;

import com.erp.auth.domain.valueobject.TenantId;
import com.erp.auth.domain.valueobject.UserId;

import java.io.Serializable;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public class PasswordResetToken implements Serializable {
    private final UUID id;
    private final UserId userId;
    private final TenantId tenantId;
    private final TokenHash tokenHash;
    private final Instant expiresAt;
    private Instant usedAt;
    private final Instant createdAt;

    public PasswordResetToken(UUID id, UserId userId, TenantId tenantId, TokenHash tokenHash, Instant expiresAt, Instant usedAt, Instant createdAt) {
        if (id == null || userId == null || tenantId == null || tokenHash == null || expiresAt == null) {
            throw new IllegalArgumentException("Required PasswordResetToken fields cannot be null");
        }
        this.id = id;
        this.userId = userId;
        this.tenantId = tenantId;
        this.tokenHash = tokenHash;
        this.expiresAt = expiresAt;
        this.usedAt = usedAt;
        this.createdAt = createdAt != null ? createdAt : Instant.now();
    }

    public PasswordResetToken(UUID id, UUID userId, UUID tenantId, String tokenHash, Instant expiresAt, Instant usedAt, Instant createdAt) {
        this(id,
             userId != null ? UserId.of(userId) : null,
             tenantId != null ? TenantId.fromString(tenantId.toString()) : null,
             tokenHash != null ? TokenHash.of(tokenHash) : null,
             expiresAt,
             usedAt,
             createdAt);
    }

    public static PasswordResetToken create(UserId userId, TenantId tenantId, TokenHash tokenHash, Instant expiresAt) {
        return new PasswordResetToken(UUID.randomUUID(), userId, tenantId, tokenHash, expiresAt, null, Instant.now());
    }

    public static PasswordResetToken create(UUID userId, UUID tenantId, String tokenHash, Instant expiresAt) {
        return create(UserId.of(userId), TenantId.fromString(tenantId.toString()), TokenHash.of(tokenHash), expiresAt);
    }

    public boolean isValid() {
        return usedAt == null && Instant.now().isBefore(expiresAt);
    }

    public void markAsUsed() {
        if (this.usedAt != null) {
            throw new IllegalStateException("Password reset token has already been used");
        }
        this.usedAt = Instant.now();
    }

    public UUID getId() {
        return id;
    }

    public TenantId getTenantIdVO() {
        return tenantId;
    }

    public UUID getTenantId() {
        return tenantId.getValue();
    }

    public UserId getUserIdVO() {
        return userId;
    }

    public UUID getUserId() {
        return userId.getValue();
    }

    public TokenHash getTokenHashVO() {
        return tokenHash;
    }

    public String getTokenHash() {
        return tokenHash.getValue();
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public Instant getUsedAt() {
        return usedAt;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof PasswordResetToken that)) return false;
        return Objects.equals(tokenHash, that.tokenHash);
    }

    @Override
    public int hashCode() {
        return Objects.hash(tokenHash);
    }
}
