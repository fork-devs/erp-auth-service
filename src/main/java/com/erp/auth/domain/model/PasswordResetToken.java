package com.erp.auth.domain.model;

import java.io.Serializable;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public class PasswordResetToken implements Serializable {
    private final UUID id;
    private final UUID userId;
    private final String tokenHash;
    private final Instant expiresAt;
    private Instant usedAt;
    private final Instant createdAt;

    public PasswordResetToken(UUID id, UUID userId, String tokenHash, Instant expiresAt, Instant usedAt, Instant createdAt) {
        if (id == null || userId == null || tokenHash == null || expiresAt == null) {
            throw new IllegalArgumentException("Campos obligatorios del PasswordResetToken no pueden ser nulos");
        }
        this.id = id;
        this.userId = userId;
        this.tokenHash = tokenHash;
        this.expiresAt = expiresAt;
        this.usedAt = usedAt;
        this.createdAt = createdAt != null ? createdAt : Instant.now();
    }

    public static PasswordResetToken create(UUID userId, String tokenHash, Instant expiresAt) {
        return new PasswordResetToken(UUID.randomUUID(), userId, tokenHash, expiresAt, null, Instant.now());
    }

    public boolean isValid() {
        return usedAt == null && Instant.now().isBefore(expiresAt);
    }

    public void markAsUsed() {
        if (this.usedAt != null) {
            throw new IllegalStateException("El token de restablecimiento ya ha sido utilizado");
        }
        this.usedAt = Instant.now();
    }

    public UUID getId() {
        return id;
    }

    public UUID getUserId() {
        return userId;
    }

    public String getTokenHash() {
        return tokenHash;
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
