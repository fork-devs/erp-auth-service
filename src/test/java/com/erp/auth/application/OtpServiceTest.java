package com.erp.auth.application;

import com.erp.auth.application.dto.command.SendOtpCommand;
import com.erp.auth.application.dto.command.VerifyOtpCommand;
import com.erp.auth.application.service.OtpService;
import com.erp.auth.domain.exception.InvalidOtpException;
import com.erp.auth.domain.model.NotificationMessage;
import com.erp.auth.domain.model.OtpVerification;
import com.erp.auth.domain.port.NotificationPort;
import com.erp.auth.domain.port.OtpVerificationRepositoryPort;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.support.DirectUnitOfWork;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class OtpServiceTest {

    @Mock
    private OtpVerificationRepositoryPort repositoryPort;

    @Mock
    private NotificationPort notificationPort;

    private OtpService otpService;

    @BeforeEach
    void setUp() {
        otpService = new OtpService(repositoryPort, notificationPort, DirectUnitOfWork.INSTANCE);
    }

    @Test
    @DisplayName("GIVEN valid email WHEN sendOtp THEN saves verification and delivers notification")
    void testSendOtp() {
        SendOtpCommand command = new SendOtpCommand("user@example.com");

        otpService.sendOtp(command);

        verify(repositoryPort).save(any(OtpVerification.class));
        verify(notificationPort).deliver(any(NotificationMessage.class));
    }

    @Test
    @DisplayName("GIVEN active otp WHEN verify with matching code THEN succeeds")
    void testVerifyOtpSuccess() throws Exception {
        String rawCode = "123456";
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        String codeHash = HexFormat.of().formatHex(digest.digest(rawCode.getBytes(StandardCharsets.UTF_8)));

        Email email = new Email("user@example.com");
        OtpVerification otp = OtpVerification.create(email, codeHash, Duration.ofMinutes(10));
        when(repositoryPort.findLatestByEmail(email)).thenReturn(Optional.of(otp));

        VerifyOtpCommand command = new VerifyOtpCommand("user@example.com", "123456");
        otpService.verifyOtp(command);

        assertThat(otp.isVerified()).isTrue();
        verify(repositoryPort).save(otp);
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
