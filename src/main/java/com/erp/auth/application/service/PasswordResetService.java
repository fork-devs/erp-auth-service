package com.erp.auth.application.service;

import com.erp.auth.application.dto.command.ForgotPasswordCommand;
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
            // Silencioso para prevenir enumeracion de usuarios: la respuesta
            // es la misma que en el caso de una cuenta existente, y no se
            // entrega ninguna notificacion.
            return;
        }

        User user = userOpt.get();

        // Invalidar los tokens anteriores y emitir el nuevo es una sola
        // operacion: si el guardado fallara tras invalidar, el usuario se
        // quedaria sin ninguna via de recuperacion.
        unitOfWork.runInTransaction(() -> {
            passwordResetTokenRepositoryPort.invalidateAllByUserId(user.getId());

            String rawToken = tokenSignerPort.generatePasswordResetToken(user.getId());
            String tokenHash = tokenSignerPort.hashToken(rawToken);
            Instant expiresAt = Instant.now().plus(tokenSignerPort.getPasswordResetTokenDuration());

            PasswordResetToken resetToken = PasswordResetToken.create(user.getId(), user.getTenantId().getValue(),
                    tokenHash, expiresAt);
            passwordResetTokenRepositoryPort.save(resetToken);

            // El token se entrega al destinatario, no se devuelve. Es la
            // unica forma de que llegue a quien puede usarlo: devolverlo en
            // la respuesta de la API se lo entregaria a quien la pide.
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

        // El restablecimiento se confirma como una sola operacion: marcar el
        // token como usado, cambiar la contrasena y revocar los refresh
        // tokens son tres escrituras que deben ocurrir juntas.
        //
        // Antes, si la escritura de la contrasena fallaba tras marcar el
        // token como usado, el usuario se quedaba con un token consumido y
        // sin poder cambiar la contrasena: un fallo que no se podia reintentar
        // sin pedir un token nuevo.
        unitOfWork.runInTransaction(() -> {
            resetToken.markAsUsed();
            passwordResetTokenRepositoryPort.save(resetToken);

            User user = userRepositoryPort.findByIdAndTenantId(resetToken.getUserId(), new TenantId(resetToken.getTenantId()))
                    .orElseThrow(() -> new UserNotFoundException(resetToken.getUserId().toString()));

            PasswordHash newPasswordHash = PasswordHash.of(passwordEncoderPort.encode(command.newPassword()));
            user.changePassword(newPasswordHash);
            user.recordSuccessfulLogin();
            userRepositoryPort.save(user);

            // Revocar todos los refresh tokens existentes por seguridad
            refreshTokenRepositoryPort.revokeAllByUserId(user.getId());
        });
    }
}
