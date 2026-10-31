package com.erp.auth.domain.model;

import com.erp.auth.domain.exception.InvalidOtpException;
import com.erp.auth.domain.exception.OtpExpiredException;
import com.erp.auth.domain.exception.OtpMaxAttemptsExceededException;
import com.erp.auth.domain.valueobject.Email;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public class OtpVerification {

    private static final int MAX_ATTEMPTS = 3;

    private final UUID id;
    private final Email email;
    private final String codeHash;
    private int attempts;
    private boolean verified;
    private final Instant expiresAt;
    private final Instant createdAt;

    public OtpVerification(UUID id, Email email, String codeHash, int attempts,
                           boolean verified, Instant expiresAt, Instant createdAt) {
        if (id == null || email == null || codeHash == null || expiresAt == null) {
            throw new IllegalArgumentException("Campos obligatorios de OtpVerification no pueden ser nulos");
        }
        this.id = id;
        this.email = email;
        this.codeHash = codeHash;
        this.attempts = attempts;
        this.verified = verified;
        this.expiresAt = expiresAt;
        this.createdAt = createdAt != null ? createdAt : Instant.now();
    }

    public static OtpVerification create(Email email, String codeHash, Duration validity) {
        Instant now = Instant.now();
        return new OtpVerification(
                UUID.randomUUID(),
                email,
                codeHash,
                0,
                false,
                now.plus(validity),
                now
        );
    }

    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }

    public void verify(String providedCodeHash) {
        if (isExpired()) {
            throw new OtpExpiredException("El código OTP ha expirado");
        }
        if (attempts >= MAX_ATTEMPTS) {
            throw new OtpMaxAttemptsExceededException("Se ha excedido el límite máximo de intentos");
        }
        if (!Objects.equals(this.codeHash, providedCodeHash)) {
            this.attempts++;
            if (this.attempts >= MAX_ATTEMPTS) {
                throw new OtpMaxAttemptsExceededException("Se ha excedido el límite máximo de intentos");
            }
            throw new InvalidOtpException("El código OTP ingresado es inválido");
        }
        this.verified = true;
    }

    public UUID getId() {
        return id;
    }

    public Email getEmail() {
        return email;
    }

    public String getCodeHash() {
        return codeHash;
    }

    public int getAttempts() {
        return attempts;
    }

    public boolean isVerified() {
        return verified;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
