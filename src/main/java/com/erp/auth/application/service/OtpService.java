package com.erp.auth.application.service;

import com.erp.auth.application.dto.command.SendOtpCommand;
import com.erp.auth.application.dto.command.VerifyOtpCommand;
import com.erp.auth.application.usecase.SendOtpUseCase;
import com.erp.auth.application.usecase.VerifyOtpUseCase;
import com.erp.auth.domain.exception.InvalidOtpException;
import com.erp.auth.domain.model.NotificationMessage;
import com.erp.auth.domain.model.OtpVerification;
import com.erp.auth.domain.port.NotificationPort;
import com.erp.auth.domain.port.OtpVerificationRepositoryPort;
import com.erp.auth.domain.port.UnitOfWork;
import com.erp.auth.domain.valueobject.Email;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.HexFormat;

public class OtpService implements SendOtpUseCase, VerifyOtpUseCase {

    private static final Duration OTP_VALIDITY = Duration.ofMinutes(10);
    private final OtpVerificationRepositoryPort repositoryPort;
    private final NotificationPort notificationPort;
    private final UnitOfWork unitOfWork;
    private final SecureRandom secureRandom = new SecureRandom();

    public OtpService(OtpVerificationRepositoryPort repositoryPort,
                      NotificationPort notificationPort,
                      UnitOfWork unitOfWork) {
        this.repositoryPort = repositoryPort;
        this.notificationPort = notificationPort;
        this.unitOfWork = unitOfWork;
    }

    @Override
    public void sendOtp(SendOtpCommand command) {
        String code = String.format("%06d", secureRandom.nextInt(1_000_000));
        String codeHash = hash(code);
        Email email = new Email(command.email());

        OtpVerification verification = OtpVerification.create(email, codeHash, OTP_VALIDITY);

        unitOfWork.runInTransaction(() -> repositoryPort.save(verification));

        notificationPort.deliver(NotificationMessage.of(
                command.email(),
                "Your DriveOS Verification Code",
                "Your verification code is: " + code + ". It expires in 10 minutes."
        ));
    }

    @Override
    public void verifyOtp(VerifyOtpCommand command) {
        Email email = new Email(command.email());
        String codeHash = hash(command.code());

        unitOfWork.runInTransaction(() -> {
            OtpVerification verification = repositoryPort.findLatestByEmail(email)
                    .orElseThrow(() -> new InvalidOtpException("No active OTP code found for " + command.email()));

            verification.verify(codeHash);
            repositoryPort.save(verification);
        });
    }

    private String hash(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encoded = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(encoded);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm unavailable", e);
        }
    }
}
