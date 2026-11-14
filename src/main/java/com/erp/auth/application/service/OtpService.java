package com.erp.auth.application.service;

import com.erp.auth.application.dto.command.SendOtpCommand;
import com.erp.auth.application.dto.command.VerifyOtpCommand;
import com.erp.auth.application.usecase.SendOtpUseCase;
import com.erp.auth.application.usecase.VerifyOtpUseCase;
import com.erp.auth.domain.exception.InvalidOtpException;
import com.erp.auth.domain.exception.OtpMaxAttemptsExceededException;
import com.erp.auth.domain.exception.OtpRateLimitExceededException;
import com.erp.auth.domain.model.NotificationMessage;
import com.erp.auth.domain.model.OtpPurpose;
import com.erp.auth.domain.model.OtpVerification;
import com.erp.auth.domain.port.NotificationPort;
import com.erp.auth.domain.port.OtpCodeHasher;
import com.erp.auth.domain.port.OtpVerificationRepositoryPort;
import com.erp.auth.domain.port.UnitOfWork;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.domain.valueobject.OtpCodeHash;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

public class OtpService implements SendOtpUseCase, VerifyOtpUseCase {

    private static final Duration OTP_VALIDITY = Duration.ofMinutes(10);
    private static final Duration COOLDOWN_PERIOD = Duration.ofSeconds(60);
    private static final Duration LOCKOUT_PERIOD = Duration.ofMinutes(15);

    private final OtpVerificationRepositoryPort repositoryPort;
    private final NotificationPort notificationPort;
    private final UnitOfWork unitOfWork;
    private final OtpCodeHasher otpCodeHasher;
    private final Clock clock;
    private final SecureRandom secureRandom = new SecureRandom();

    public OtpService(OtpVerificationRepositoryPort repositoryPort,
                      NotificationPort notificationPort,
                      UnitOfWork unitOfWork,
                      OtpCodeHasher otpCodeHasher,
                      Clock clock) {
        this.repositoryPort = Objects.requireNonNull(repositoryPort, "repositoryPort cannot be null");
        this.notificationPort = Objects.requireNonNull(notificationPort, "notificationPort cannot be null");
        this.unitOfWork = Objects.requireNonNull(unitOfWork, "unitOfWork cannot be null");
        this.otpCodeHasher = Objects.requireNonNull(otpCodeHasher, "otpCodeHasher cannot be null");
        this.clock = clock != null ? clock : Clock.systemUTC();
    }

    @Override
    public void sendOtp(SendOtpCommand command) {
        Email email = new Email(command.email());
        Instant now = clock.instant();

        Optional<OtpVerification> latestOpt = repositoryPort.findLatestByEmail(email);
        if (latestOpt.isPresent()) {
            OtpVerification existing = latestOpt.get();
            if (existing.getAttempts() >= OtpVerification.MAX_ATTEMPTS
                    && now.isBefore(existing.getCreatedAt().plus(LOCKOUT_PERIOD))) {
                throw new OtpMaxAttemptsExceededException("Maximum OTP verification attempts exceeded. Please try again in 15 minutes.");
            }
            if (!existing.isVerified() && now.isBefore(existing.getCreatedAt().plus(COOLDOWN_PERIOD))) {
                throw new OtpRateLimitExceededException("Please wait at least 60 seconds before requesting a new OTP code");
            }
        }

        String code = String.format("%06d", secureRandom.nextInt(1_000_000));
        OtpCodeHash codeHash = otpCodeHasher.hash(code);

        OtpVerification verification = OtpVerification.create(
                null,
                null,
                email,
                OtpPurpose.EMAIL_VERIFICATION,
                codeHash,
                OTP_VALIDITY,
                clock
        );

        unitOfWork.runInTransaction(() -> {
            repositoryPort.invalidateAllPendingByEmail(email);
            repositoryPort.save(verification);
        });

        notificationPort.deliver(NotificationMessage.of(
                command.email(),
                "Your DriveOS Verification Code",
                "Your verification code is: " + code + ". It expires in 10 minutes."
        ));
    }

    @Override
    public void verifyOtp(VerifyOtpCommand command) {
        Email email = new Email(command.email());

        unitOfWork.runInTransaction(() -> {
            OtpVerification verification = repositoryPort.findLatestByEmail(email)
                    .orElseThrow(() -> new InvalidOtpException("No active OTP code found for " + command.email()));

            try {
                verification.verify(command.code(), otpCodeHasher, clock);
                repositoryPort.save(verification);
            } catch (InvalidOtpException e) {
                repositoryPort.incrementAttempts(verification.getId());
                throw e;
            }
        });
    }
}
