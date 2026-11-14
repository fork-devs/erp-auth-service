package com.erp.auth.application;

import com.erp.auth.application.dto.command.SendOtpCommand;
import com.erp.auth.application.dto.command.VerifyOtpCommand;
import com.erp.auth.application.service.OtpService;
import com.erp.auth.domain.exception.InvalidOtpException;
import com.erp.auth.domain.exception.OtpMaxAttemptsExceededException;
import com.erp.auth.domain.exception.OtpRateLimitExceededException;
import com.erp.auth.domain.model.NotificationMessage;
import com.erp.auth.domain.model.OtpPurpose;
import com.erp.auth.domain.model.OtpVerification;
import com.erp.auth.domain.port.NotificationPort;
import com.erp.auth.domain.port.OtpCodeHasher;
import com.erp.auth.domain.port.OtpVerificationRepositoryPort;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.domain.valueobject.OtpCodeHash;
import com.erp.auth.domain.valueobject.OtpVerificationId;
import com.erp.auth.support.DirectUnitOfWork;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.HexFormat;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("Application - OtpService Security & Lifecycle Test")
class OtpServiceTest {

    @Mock
    private OtpVerificationRepositoryPort repositoryPort;

    @Mock
    private NotificationPort notificationPort;

    private OtpCodeHasher otpCodeHasher;
    private Clock clock;
    private Instant now;
    private OtpService otpService;

    @BeforeEach
    void setUp() {
        now = Instant.parse("2026-11-07T14:00:00Z");
        clock = Clock.fixed(now, ZoneId.of("UTC"));
        otpCodeHasher = raw -> {
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] digest = md.digest(raw.getBytes(StandardCharsets.UTF_8));
                return new OtpCodeHash(HexFormat.of().formatHex(digest));
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        };
        otpService = new OtpService(repositoryPort, notificationPort, DirectUnitOfWork.INSTANCE, otpCodeHasher, clock);
    }

    @Test
    @DisplayName("GIVEN valid email WHEN sendOtp THEN invalidates pending, saves verification, and delivers notification")
    void testSendOtp() {
        Email email = new Email("user@example.com");
        when(repositoryPort.findLatestByEmail(email)).thenReturn(Optional.empty());

        SendOtpCommand command = new SendOtpCommand("user@example.com");
        otpService.sendOtp(command);

        verify(repositoryPort).invalidateAllPendingByEmail(email);
        verify(repositoryPort).save(any(OtpVerification.class));
        verify(notificationPort).deliver(any(NotificationMessage.class));
    }

    @Test
    @DisplayName("GIVEN existing OTP sent 10s ago WHEN sendOtp again THEN throws OtpRateLimitExceededException")
    void testSendOtpRateLimitCooldown() {
        Email email = new Email("user@example.com");
        OtpCodeHash hash = otpCodeHasher.hash("123456");
        OtpVerification recent = OtpVerification.reconstitute(
                OtpVerificationId.generate(),
                null,
                null,
                email,
                OtpPurpose.EMAIL_VERIFICATION,
                hash,
                0,
                false,
                now.plus(Duration.ofMinutes(10)),
                now.minusSeconds(10) // created 10 seconds ago (less than 60s cooldown)
        );
        when(repositoryPort.findLatestByEmail(email)).thenReturn(Optional.of(recent));

        SendOtpCommand command = new SendOtpCommand("user@example.com");
        assertThatThrownBy(() -> otpService.sendOtp(command))
                .isInstanceOf(OtpRateLimitExceededException.class)
                .hasMessageContaining("wait at least 60 seconds");

        verify(repositoryPort, never()).save(any());
        verify(notificationPort, never()).deliver(any());
    }

    @Test
    @DisplayName("GIVEN existing OTP with max attempts exceeded WHEN sendOtp within lockout window THEN throws OtpMaxAttemptsExceededException")
    void testSendOtpLockout() {
        Email email = new Email("user@example.com");
        OtpCodeHash hash = otpCodeHasher.hash("123456");
        OtpVerification locked = OtpVerification.reconstitute(
                OtpVerificationId.generate(),
                null,
                null,
                email,
                OtpPurpose.EMAIL_VERIFICATION,
                hash,
                3, // max attempts exceeded
                false,
                now.plus(Duration.ofMinutes(5)),
                now.minusSeconds(300) // created 5 minutes ago (inside 15m lockout)
        );
        when(repositoryPort.findLatestByEmail(email)).thenReturn(Optional.of(locked));

        SendOtpCommand command = new SendOtpCommand("user@example.com");
        assertThatThrownBy(() -> otpService.sendOtp(command))
                .isInstanceOf(OtpMaxAttemptsExceededException.class)
                .hasMessageContaining("Maximum OTP verification attempts exceeded");

        verify(repositoryPort, never()).save(any());
        verify(notificationPort, never()).deliver(any());
    }

    @Test
    @DisplayName("GIVEN active otp WHEN verify with matching raw code THEN marks verified and saves")
    void testVerifyOtpSuccess() {
        String rawCode = "123456";
        OtpCodeHash codeHash = otpCodeHasher.hash(rawCode);
        Email email = new Email("user@example.com");
        OtpVerification otp = OtpVerification.create(null, null, email, OtpPurpose.EMAIL_VERIFICATION, codeHash, Duration.ofMinutes(10), clock);

        when(repositoryPort.findLatestByEmail(email)).thenReturn(Optional.of(otp));

        VerifyOtpCommand command = new VerifyOtpCommand("user@example.com", "123456");
        otpService.verifyOtp(command);

        assertThat(otp.isVerified()).isTrue();
        verify(repositoryPort).save(otp);
    }

    @Test
    @DisplayName("GIVEN active otp WHEN verify with incorrect code THEN calls atomic incrementAttempts in DB and rethrows")
    void testVerifyOtpFailureIncrementsDb() {
        String rawCode = "123456";
        OtpCodeHash codeHash = otpCodeHasher.hash(rawCode);
        Email email = new Email("user@example.com");
        OtpVerification otp = OtpVerification.create(null, null, email, OtpPurpose.EMAIL_VERIFICATION, codeHash, Duration.ofMinutes(10), clock);

        when(repositoryPort.findLatestByEmail(email)).thenReturn(Optional.of(otp));

        VerifyOtpCommand command = new VerifyOtpCommand("user@example.com", "999999");
        assertThatThrownBy(() -> otpService.verifyOtp(command))
                .isInstanceOf(InvalidOtpException.class);

        verify(repositoryPort).incrementAttempts(otp.getId());
    }

    @Test
    @DisplayName("GIVEN non-existing otp WHEN verify THEN throws InvalidOtpException")
    void testVerifyOtpNotFound() {
        when(repositoryPort.findLatestByEmail(any(Email.class))).thenReturn(Optional.empty());

        VerifyOtpCommand command = new VerifyOtpCommand("unknown@example.com", "123456");
        assertThatThrownBy(() -> otpService.verifyOtp(command))
                .isInstanceOf(InvalidOtpException.class);
    }
}
