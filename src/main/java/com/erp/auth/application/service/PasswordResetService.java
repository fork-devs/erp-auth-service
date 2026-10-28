package com.erp.auth.application.service;

import com.erp.auth.application.dto.command.ForgotPasswordCommand;
import com.erp.auth.application.logging.AuthEventLogger;
import com.erp.auth.application.dto.command.ResetPasswordCommand;
import com.erp.auth.application.usecase.PasswordResetUseCase;
import com.erp.auth.domain.exception.InvalidTokenException;
import com.erp.auth.domain.exception.TokenExpiredException;
import com.erp.auth.domain.exception.UserNotFoundException;
import com.erp.auth.domain.model.PasswordResetToken;
import com.erp.auth.domain.model.User;
import com.erp.auth.domain.model.NotificationMessage;
import com.erp.auth.domain.port.NotificationPort;
import com.erp.auth.domain.port.PasswordEncoderPort;
import com.erp.auth.domain.port.PasswordResetTokenRepositoryPort;
import com.erp.auth.domain.port.RefreshTokenRepositoryPort;
import com.erp.auth.domain.port.TokenSignerPort;
import com.erp.auth.domain.port.UnitOfWork;
import com.erp.auth.domain.port.UserRepositoryPort;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.domain.valueobject.PasswordHash;
import com.erp.auth.domain.valueobject.TenantId;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;

public class PasswordResetService implements PasswordResetUseCase {

    private final UserRepositoryPort userRepositoryPort;
    private final PasswordResetTokenRepositoryPort passwordResetTokenRepositoryPort;
    private final RefreshTokenRepositoryPort refreshTokenRepositoryPort;
    private final PasswordEncoderPort passwordEncoderPort;
    private final TokenSignerPort tokenSignerPort;
    private final NotificationPort notificationPort;
    private final UnitOfWork unitOfWork;

    public PasswordResetService(
            UserRepositoryPort userRepositoryPort,
            PasswordResetTokenRepositoryPort passwordResetTokenRepositoryPort,
            RefreshTokenRepositoryPort refreshTokenRepositoryPort,
            PasswordEncoderPort passwordEncoderPort,
            TokenSignerPort tokenSignerPort,
            NotificationPort notificationPort,
            UnitOfWork unitOfWork) {
        this.userRepositoryPort = userRepositoryPort;
        this.passwordResetTokenRepositoryPort = passwordResetTokenRepositoryPort;
        this.refreshTokenRepositoryPort = refreshTokenRepositoryPort;
        this.passwordEncoderPort = passwordEncoderPort;
        this.tokenSignerPort = tokenSignerPort;
        this.notificationPort = notificationPort;
        this.unitOfWork = unitOfWork;
    }

    @Override
    public void requestPasswordReset(ForgotPasswordCommand command) {
        if (command.email() == null || command.email().trim().isEmpty()) {
            throw new IllegalArgumentException("El correo electrónico es obligatorio");
        }

        if (command.tenantId() == null) {
            throw new IllegalArgumentException("El identificador de taller es obligatorio para restablecer la contrasena");
        }

        Email email = Email.of(command.email());
        Optional<User> userOpt = userRepositoryPort.findByEmailAndTenantId(email, new TenantId(command.tenantId()));

        if (userOpt.isEmpty()) {
            // Silent return to prevent user enumeration: response matches
            // existing account behavior, and no notification is sent.
            return;
        }

        User user = userOpt.get();

        // Invalidation of previous tokens and issuance of the new token occur
        // atomically: failure after invalidation would strand the user without recovery options.
        unitOfWork.runInTransaction(() -> {
            passwordResetTokenRepositoryPort.invalidateAllByUserId(user.getId());

            String rawToken = tokenSignerPort.generatePasswordResetToken(user.getId());
            String tokenHash = tokenSignerPort.hashToken(rawToken);
            Instant expiresAt = Instant.now().plus(tokenSignerPort.getPasswordResetTokenDuration());

            PasswordResetToken resetToken = PasswordResetToken.create(user.getId(), user.getTenantId().getValue(),
                    tokenHash, expiresAt);
            passwordResetTokenRepositoryPort.save(resetToken);

            // Deliver token to recipient rather than returning it in API response.
            // Direct return would expose credentials to whoever invoked the endpoint.
            AuthEventLogger.registrar("restablecimiento_solicitado", user.getTenantId().getValue(), user.getId(),
                    null, "ok", Map.of());
            notificationPort.deliver(NotificationMessage.of(
                    user.getEmail().getValue(),
                    "Restablecimiento de contrasena",
                    "Use este token para restablecer su contrasena: " + rawToken));
        });
    }

    @Override
    public void resetPassword(ResetPasswordCommand command) {
        if (command.token() == null || command.newPassword() == null) {
            throw new IllegalArgumentException("Token y nueva contraseña son obligatorios");
        }

        if (command.tenantId() == null) {
            throw new IllegalArgumentException("El identificador de taller es obligatorio para restablecer la contrasena");
        }

        String tokenHash = tokenSignerPort.hashToken(command.token().trim());
        PasswordResetToken resetToken = passwordResetTokenRepositoryPort.findByTokenHashAndTenantId(tokenHash, command.tenantId())
                .orElseThrow(() -> new InvalidTokenException("Token de restablecimiento inválido"));

        if (!resetToken.isValid()) {
            throw new TokenExpiredException();
        }

        // Reset is committed as a single atomic operation: marking the token
        // as used, changing the password, and revoking existing refresh tokens
        // must succeed together.
        unitOfWork.runInTransaction(() -> {
            resetToken.markAsUsed();
            passwordResetTokenRepositoryPort.save(resetToken);

            User user = userRepositoryPort.findByIdAndTenantId(resetToken.getUserId(), new TenantId(resetToken.getTenantId()))
                    .orElseThrow(() -> new UserNotFoundException(resetToken.getUserId().toString()));

            PasswordHash newPasswordHash = PasswordHash.of(passwordEncoderPort.encode(command.newPassword()));
            user.changePassword(newPasswordHash);
            user.recordSuccessfulLogin();
            userRepositoryPort.save(user);

            // Revoke all existing refresh tokens for security
            refreshTokenRepositoryPort.revokeAllByUserId(user.getId());
        });
    }
}
