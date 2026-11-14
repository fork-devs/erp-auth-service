package com.erp.auth.domain;

import com.erp.auth.domain.exception.InvalidOtpException;
import com.erp.auth.domain.exception.OtpAlreadyVerifiedException;
import com.erp.auth.domain.exception.OtpExpiredException;
import com.erp.auth.domain.exception.OtpMaxAttemptsExceededException;
import com.erp.auth.domain.model.OtpPurpose;
import com.erp.auth.domain.model.OtpVerification;
import com.erp.auth.domain.port.OtpCodeHasher;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.domain.valueobject.OtpCodeHash;
import com.erp.auth.domain.valueobject.OtpVerificationId;
import com.erp.auth.domain.valueobject.TenantId;
import com.erp.auth.domain.valueobject.UserId;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.HexFormat;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("Domain - OtpVerification Hardening & State Machine Test")
class OtpVerificationTest {

    private static final String RAW_CODE = "123456";
    private OtpCodeHasher hasher;
    private Clock clock;
    private Instant fixedInstant;

    @BeforeEach
    void setUp() {
        fixedInstant = Instant.parse("2026-11-07T12:00:00Z");
        clock = Clock.fixed(fixedInstant, ZoneId.of("UTC"));
        hasher = raw -> {
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] digest = md.digest(raw.getBytes(StandardCharsets.UTF_8));
                return new OtpCodeHash(HexFormat.of().formatHex(digest));
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        };
    }

    @Test
    @DisplayName("GIVEN valid otp WHEN verify with correct code THEN marked as verified")
    void testSuccessfulVerification() {
        Email email = new Email("test@example.com");
        OtpCodeHash codeHash = hasher.hash(RAW_CODE);
        OtpVerification otp = OtpVerification.create(
                TenantId.generate(),
                UserId.generate(),
                email,
                OtpPurpose.EMAIL_VERIFICATION,
                codeHash,
                Duration.ofMinutes(10),
                clock
        );

        assertThat(otp.isVerified()).isFalse();
        assertThat(otp.isExpired(clock)).isFalse();

        otp.verify(RAW_CODE, hasher, clock);

        assertThat(otp.isVerified()).isTrue();
        assertThat(otp.getAttempts()).isEqualTo(0);
    }

    @Test
    @DisplayName("GIVEN already verified otp WHEN verify again THEN throws OtpAlreadyVerifiedException")
    void testAlreadyVerifiedOtpCannotBeReused() {
        Email email = new Email("test@example.com");
        OtpCodeHash codeHash = hasher.hash(RAW_CODE);
        OtpVerification otp = OtpVerification.create(
                TenantId.generate(),
                UserId.generate(),
                email,
                OtpPurpose.EMAIL_VERIFICATION,
                codeHash,
                Duration.ofMinutes(10),
                clock
        );

        otp.verify(RAW_CODE, hasher, clock);
        assertThat(otp.isVerified()).isTrue();

        assertThatThrownBy(() -> otp.verify(RAW_CODE, hasher, clock))
                .isInstanceOf(OtpAlreadyVerifiedException.class)
                .hasMessageContaining("already been verified");
    }

    @Test
    @DisplayName("GIVEN expired otp WHEN verify THEN throws OtpExpiredException using injected Clock")
    void testExpiredOtpThrowsException() {
        Email email = new Email("test@example.com");
        OtpCodeHash codeHash = hasher.hash(RAW_CODE);
        OtpVerification otp = OtpVerification.reconstitute(
                OtpVerificationId.generate(),
                TenantId.generate(),
                UserId.generate(),
                email,
                OtpPurpose.EMAIL_VERIFICATION,
                codeHash,
                0,
                false,
                fixedInstant.minusSeconds(10),
                fixedInstant.minusSeconds(600)
        );

        assertThat(otp.isExpired(clock)).isTrue();
        assertThatThrownBy(() -> otp.verify(RAW_CODE, hasher, clock))
                .isInstanceOf(OtpExpiredException.class);
    }

    @Test
    @DisplayName("GIVEN incorrect code WHEN verify THEN increments attempts and throws InvalidOtpException")
    void testIncorrectCodeIncrementsAttempts() {
        Email email = new Email("test@example.com");
        OtpCodeHash codeHash = hasher.hash(RAW_CODE);
        OtpVerification otp = OtpVerification.create(
                TenantId.generate(),
                UserId.generate(),
                email,
                OtpPurpose.EMAIL_VERIFICATION,
                codeHash,
                Duration.ofMinutes(10),
                clock
        );

        assertThatThrownBy(() -> otp.verify("999999", hasher, clock))
                .isInstanceOf(InvalidOtpException.class);

        assertThat(otp.getAttempts()).isEqualTo(1);
        assertThat(otp.isVerified()).isFalse();
    }

    @Test
    @DisplayName("GIVEN 3 failed attempts WHEN verify again THEN throws OtpMaxAttemptsExceededException")
    void testMaxAttemptsExceededThrowsException() {
        Email email = new Email("test@example.com");
        OtpCodeHash codeHash = hasher.hash(RAW_CODE);
        OtpVerification otp = OtpVerification.create(
                TenantId.generate(),
                UserId.generate(),
                email,
                OtpPurpose.EMAIL_VERIFICATION,
                codeHash,
                Duration.ofMinutes(10),
                clock
        );

        assertThatThrownBy(() -> otp.verify("000001", hasher, clock)).isInstanceOf(InvalidOtpException.class);
        assertThatThrownBy(() -> otp.verify("000002", hasher, clock)).isInstanceOf(InvalidOtpException.class);
        assertThatThrownBy(() -> otp.verify("000003", hasher, clock)).isInstanceOf(OtpMaxAttemptsExceededException.class);

        assertThat(otp.getAttempts()).isEqualTo(3);
        assertThatThrownBy(() -> otp.verify(RAW_CODE, hasher, clock)).isInstanceOf(OtpMaxAttemptsExceededException.class);
    }

    @Test
    @DisplayName("GIVEN invalid creation arguments WHEN create THEN throws IllegalArgumentException")
    void testInvalidCreationParameters() {
        Email email = new Email("test@example.com");
        OtpCodeHash codeHash = hasher.hash(RAW_CODE);

        assertThatThrownBy(() -> OtpVerification.create(null, null, email, OtpPurpose.EMAIL_VERIFICATION, codeHash, Duration.ZERO, clock))
                .isInstanceOf(IllegalArgumentException.class);

        assertThatThrownBy(() -> OtpVerification.create(null, null, email, OtpPurpose.EMAIL_VERIFICATION, codeHash, Duration.ofMinutes(-5), clock))
                .isInstanceOf(IllegalArgumentException.class);

        assertThatThrownBy(() -> OtpVerification.create(null, null, email, OtpPurpose.EMAIL_VERIFICATION, codeHash, Duration.ofMinutes(10), null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    @DisplayName("GIVEN OtpCodeHash WHEN toString invoked THEN returns masked string")
    void testCodeHashToStringIsMasked() {
        OtpCodeHash codeHash = hasher.hash(RAW_CODE);
        assertThat(codeHash.toString()).isEqualTo("********");
    }
}
