package com.erp.auth.domain.model;

import com.erp.auth.domain.exception.InvalidOtpException;
import com.erp.auth.domain.exception.OtpAlreadyVerifiedException;
import com.erp.auth.domain.exception.OtpExpiredException;
import com.erp.auth.domain.exception.OtpMaxAttemptsExceededException;
import com.erp.auth.domain.port.OtpCodeHasher;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.domain.valueobject.OtpCodeHash;
import com.erp.auth.domain.valueobject.OtpVerificationId;
import com.erp.auth.domain.valueobject.TenantId;
import com.erp.auth.domain.valueobject.UserId;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

public class OtpVerification {

    public static final int MAX_ATTEMPTS = 3;

    private final OtpVerificationId id;
    private final TenantId tenantId;
    private final UserId userId;
    private final Email email;
    private final OtpPurpose purpose;
    private final OtpCodeHash codeHash;
    private int attempts;
    private boolean verified;
    private final Instant expiresAt;
    private final Instant createdAt;

    private OtpVerification(OtpVerificationId id,
                           TenantId tenantId,
                           UserId userId,
                           Email email,
                           OtpPurpose purpose,
                           OtpCodeHash codeHash,
                           int attempts,
                           boolean verified,
                           Instant expiresAt,
                           Instant createdAt) {
        if (id == null) {
            throw new IllegalArgumentException("OtpVerificationId cannot be null");
        }
        if (email == null) {
            throw new IllegalArgumentException("Email cannot be null");
        }
        if (purpose == null) {
            throw new IllegalArgumentException("OtpPurpose cannot be null");
        }
        if (codeHash == null) {
            throw new IllegalArgumentException("OtpCodeHash cannot be null");
        }
        if (expiresAt == null) {
            throw new IllegalArgumentException("expiresAt cannot be null");
        }
        if (attempts < 0) {
            throw new IllegalArgumentException("Attempts cannot be negative");
        }
        this.id = id;
        this.tenantId = tenantId;
        this.userId = userId;
        this.email = email;
        this.purpose = purpose;
        this.codeHash = codeHash;
        this.attempts = attempts;
        this.verified = verified;
        this.expiresAt = expiresAt;
        this.createdAt = createdAt != null ? createdAt : Instant.now();
    }

    public static OtpVerification create(TenantId tenantId,
                                         UserId userId,
                                         Email email,
                                         OtpPurpose purpose,
                                         OtpCodeHash codeHash,
                                         Duration validity,
                                         Clock clock) {
        Objects.requireNonNull(clock, "Clock cannot be null");
        if (validity == null || validity.isNegative() || validity.isZero()) {
            throw new IllegalArgumentException("Validity duration must be strictly positive");
        }
        Instant now = clock.instant();
        Instant expiresAt = now.plus(validity);
        if (!expiresAt.isAfter(now)) {
            throw new IllegalArgumentException("Calculated expiresAt must be in the future");
        }
        return new OtpVerification(
                OtpVerificationId.generate(),
                tenantId,
                userId,
                email,
                purpose != null ? purpose : OtpPurpose.EMAIL_VERIFICATION,
                codeHash,
                0,
                false,
                expiresAt,
                now
        );
    }

    public static OtpVerification reconstitute(OtpVerificationId id,
                                               TenantId tenantId,
                                               UserId userId,
                                               Email email,
                                               OtpPurpose purpose,
                                               OtpCodeHash codeHash,
                                               int attempts,
                                               boolean verified,
                                               Instant expiresAt,
                                               Instant createdAt) {
        return new OtpVerification(id, tenantId, userId, email, purpose, codeHash, attempts, verified, expiresAt, createdAt);
    }

    public boolean isExpired(Clock clock) {
        Objects.requireNonNull(clock, "Clock cannot be null");
        return clock.instant().isAfter(expiresAt);
    }

    public void verify(String rawCode, OtpCodeHasher hasher, Clock clock) {
        Objects.requireNonNull(clock, "Clock cannot be null");
        Objects.requireNonNull(hasher, "OtpCodeHasher cannot be null");
        if (rawCode == null || rawCode.trim().isEmpty()) {
            throw new InvalidOtpException("OTP raw code cannot be blank");
        }

        if (this.verified) {
            throw new OtpAlreadyVerifiedException("OTP code has already been verified and cannot be reused");
        }

        if (isExpired(clock)) {
            throw new OtpExpiredException("OTP code has expired");
        }

        if (this.attempts >= MAX_ATTEMPTS) {
            throw new OtpMaxAttemptsExceededException("Maximum OTP verification attempts exceeded");
        }

        OtpCodeHash providedHash = hasher.hash(rawCode.trim());
        byte[] expected = this.codeHash.value().getBytes(StandardCharsets.UTF_8);
        byte[] actual = providedHash.value().getBytes(StandardCharsets.UTF_8);

        if (!MessageDigest.isEqual(expected, actual)) {
            this.attempts++;
            if (this.attempts >= MAX_ATTEMPTS) {
                throw new OtpMaxAttemptsExceededException("Maximum OTP verification attempts exceeded");
            }
            throw new InvalidOtpException("Invalid OTP code provided");
        }

        this.verified = true;
    }

    public void recordFailedAttempt() {
        this.attempts++;
    }

    public OtpVerificationId getId() {
        return id;
    }

    public TenantId getTenantId() {
        return tenantId;
    }

    public UserId getUserId() {
        return userId;
    }

    public Email getEmail() {
        return email;
    }

    public OtpPurpose getPurpose() {
        return purpose;
    }

    public OtpCodeHash getCodeHash() {
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
