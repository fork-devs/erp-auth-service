package com.erp.auth.domain;

import com.erp.auth.domain.exception.InvalidOtpException;
import com.erp.auth.domain.exception.OtpExpiredException;
import com.erp.auth.domain.exception.OtpMaxAttemptsExceededException;
import com.erp.auth.domain.model.OtpVerification;
import com.erp.auth.domain.valueobject.Email;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class OtpVerificationTest {

    @Test
    @DisplayName("GIVEN valid otp WHEN verify with correct hash THEN marked as verified")
    void testSuccessfulVerification() {
        Email email = new Email("test@example.com");
        String codeHash = "hash123";
        OtpVerification otp = OtpVerification.create(email, codeHash, Duration.ofMinutes(10));

        assertThat(otp.isVerified()).isFalse();
        assertThat(otp.isExpired()).isFalse();

        otp.verify("hash123");

        assertThat(otp.isVerified()).isTrue();
        assertThat(otp.getAttempts()).isEqualTo(0);
    }

    @Test
    @DisplayName("GIVEN expired otp WHEN verify THEN throws OtpExpiredException")
    void testExpiredOtpThrowsException() {
        Email email = new Email("test@example.com");
        OtpVerification otp = new OtpVerification(
                UUID.randomUUID(),
                email,
                "hash123",
                0,
                false,
                Instant.now().minusSeconds(10),
                Instant.now().minusSeconds(600)
        );

        assertThat(otp.isExpired()).isTrue();
        assertThatThrownBy(() -> otp.verify("hash123"))
                .isInstanceOf(OtpExpiredException.class);
    }

    @Test
    @DisplayName("GIVEN incorrect code WHEN verify THEN increments attempts and throws InvalidOtpException")
    void testIncorrectCodeIncrementsAttempts() {
        Email email = new Email("test@example.com");
        OtpVerification otp = OtpVerification.create(email, "hash123", Duration.ofMinutes(10));

        assertThatThrownBy(() -> otp.verify("wrong_hash"))
                .isInstanceOf(InvalidOtpException.class);

        assertThat(otp.getAttempts()).isEqualTo(1);
        assertThat(otp.isVerified()).isFalse();
    }

    @Test
    @DisplayName("GIVEN 3 failed attempts WHEN verify again THEN throws OtpMaxAttemptsExceededException")
    void testMaxAttemptsExceededThrowsException() {
        Email email = new Email("test@example.com");
        OtpVerification otp = OtpVerification.create(email, "hash123", Duration.ofMinutes(10));

        assertThatThrownBy(() -> otp.verify("wrong1")).isInstanceOf(InvalidOtpException.class);
        assertThatThrownBy(() -> otp.verify("wrong2")).isInstanceOf(InvalidOtpException.class);
        assertThatThrownBy(() -> otp.verify("wrong3")).isInstanceOf(OtpMaxAttemptsExceededException.class);

        assertThat(otp.getAttempts()).isEqualTo(3);
        assertThatThrownBy(() -> otp.verify("hash123")).isInstanceOf(OtpMaxAttemptsExceededException.class);
    }
}
