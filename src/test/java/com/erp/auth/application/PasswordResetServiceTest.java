package com.erp.auth.application;

import com.erp.auth.application.dto.command.ResetPasswordCommand;
import com.erp.auth.application.service.PasswordResetService;
import com.erp.auth.domain.exception.InvalidTokenException;
import com.erp.auth.domain.model.PasswordResetToken;
import com.erp.auth.domain.model.Role;
import com.erp.auth.domain.model.RoleCode;
import com.erp.auth.domain.model.TokenHash;
import com.erp.auth.domain.model.User;
import com.erp.auth.domain.port.NotificationPort;
import com.erp.auth.domain.port.PasswordEncoderPort;
import com.erp.auth.domain.port.PasswordResetTokenRepositoryPort;
import com.erp.auth.domain.port.RefreshTokenRepositoryPort;
import com.erp.auth.domain.port.TokenSignerPort;
import com.erp.auth.domain.port.UserRepositoryPort;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.domain.valueobject.PasswordHash;
import com.erp.auth.domain.valueobject.TenantId;
import com.erp.auth.domain.valueobject.UserId;
import com.erp.auth.support.DirectUnitOfWork;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("Application - PasswordResetService Unit Test")
class PasswordResetServiceTest {

    @Mock
    private UserRepositoryPort userRepositoryPort;

    @Mock
    private PasswordResetTokenRepositoryPort passwordResetTokenRepositoryPort;

    @Mock
    private RefreshTokenRepositoryPort refreshTokenRepositoryPort;

    @Mock
    private PasswordEncoderPort passwordEncoderPort;

    @Mock
    private TokenSignerPort tokenSignerPort;

    @Mock
    private NotificationPort notificationPort;

    private PasswordResetService passwordResetService;
    private TenantId tenantId;
    private UserId userId;
    private User sampleUser;
    private final String rawToken = "sample-raw-reset-token-123";
    private final String hashStr = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    @BeforeEach
    void setUp() {
        passwordResetService = new PasswordResetService(
                userRepositoryPort,
                passwordResetTokenRepositoryPort,
                refreshTokenRepositoryPort,
                passwordEncoderPort,
                tokenSignerPort,
                notificationPort,
                DirectUnitOfWork.INSTANCE
        );

        tenantId = TenantId.generate();
        userId = new UserId(UUID.randomUUID());
        sampleUser = User.create(
                tenantId,
                Email.of("admin@taller.pe"),
                PasswordHash.of("$2a$12$hashedOldPassword"),
                "Admin Taller",
                Set.of(Role.create(RoleCode.WORKSHOP_ADMIN, "Admin"))
        );
    }

    @Test
    @DisplayName("Debe restablecer contraseña, marcar token como usado, e invalidar otros tokens de restablecimiento y refresh tokens")
    void shouldResetPasswordAndInvalidateAllPendingTokensAndRefreshTokens() {
        PasswordResetToken resetToken = PasswordResetToken.create(
                userId,
                tenantId,
                TokenHash.of(hashStr),
                Instant.now().plus(Duration.ofHours(2))
        );

        ResetPasswordCommand command = new ResetPasswordCommand(rawToken, "NuevaContrasenaSegura#2026", tenantId.value());

        when(tokenSignerPort.hashToken(rawToken)).thenReturn(hashStr);
        when(passwordResetTokenRepositoryPort.findByTokenHashAndTenantId(hashStr, tenantId.value()))
                .thenReturn(Optional.of(resetToken));
        when(userRepositoryPort.findByIdAndTenantId(resetToken.getUserId(), tenantId))
                .thenReturn(Optional.of(sampleUser));
        when(passwordEncoderPort.encode("NuevaContrasenaSegura#2026")).thenReturn("$2a$12$encodedNewPasswordHash");

        passwordResetService.resetPassword(command);

        assertTrue(resetToken.isUsed(), "El token de restablecimiento debe quedar marcado como usado");
        verify(passwordResetTokenRepositoryPort).save(resetToken);
        verify(userRepositoryPort).save(sampleUser);
        // Invalidación de todos los demás tokens de restablecimiento del usuario en este tenant
        verify(passwordResetTokenRepositoryPort).invalidateAllByUserId(new UserId(sampleUser.getId()), tenantId);
        // Revocación de todos los refresh tokens existentes del usuario en este tenant
        verify(refreshTokenRepositoryPort).revokeAllByUserId(new UserId(sampleUser.getId()), tenantId);
    }

    @Test
    @DisplayName("Debe rechazar token de restablecimiento si ya fue utilizado previamente (single-use enforcement)")
    void shouldRejectAlreadyUsedPasswordResetToken() {
        PasswordResetToken usedToken = new PasswordResetToken(
                UUID.randomUUID(),
                userId,
                tenantId,
                TokenHash.of(hashStr),
                Instant.now().plus(Duration.ofHours(1)),
                Instant.now().minus(Duration.ofMinutes(5)), // already used
                Instant.now().minus(Duration.ofMinutes(10))
        );

        ResetPasswordCommand command = new ResetPasswordCommand(rawToken, "NuevaContrasenaSegura#2026", tenantId.value());

        when(tokenSignerPort.hashToken(rawToken)).thenReturn(hashStr);
        when(passwordResetTokenRepositoryPort.findByTokenHashAndTenantId(hashStr, tenantId.value()))
                .thenReturn(Optional.of(usedToken));

        assertThrows(InvalidTokenException.class, () -> passwordResetService.resetPassword(command));
        verify(userRepositoryPort, never()).save(any());
    }
}
