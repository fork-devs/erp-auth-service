package com.erp.auth.application;

import com.erp.auth.application.dto.command.LoginCommand;
import com.erp.auth.application.dto.result.AuthResult;
import com.erp.auth.application.service.AuthenticateUserService;
import com.erp.auth.domain.exception.AccountLockedException;
import com.erp.auth.domain.exception.InvalidCredentialsException;
import com.erp.auth.domain.model.RefreshToken;
import com.erp.auth.domain.model.Role;
import com.erp.auth.domain.model.RoleCode;
import com.erp.auth.domain.model.User;
import com.erp.auth.domain.port.PasswordEncoderPort;
import com.erp.auth.domain.port.RefreshTokenRepositoryPort;
import com.erp.auth.domain.port.TokenSignerPort;
import com.erp.auth.domain.port.UserRepositoryPort;
import com.erp.auth.support.DirectUnitOfWork;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.domain.valueobject.PasswordHash;
import com.erp.auth.domain.valueobject.TenantId;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Duration;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthenticateUserServiceTest {

    @Mock
    private UserRepositoryPort userRepositoryPort;

    @Mock
    private RefreshTokenRepositoryPort refreshTokenRepositoryPort;

    @Mock
    private PasswordEncoderPort passwordEncoderPort;

    @Mock
    private TokenSignerPort tokenSignerPort;

    private AuthenticateUserService authenticateUserService;
    private TenantId tenantId;

    private User sampleUser;
    private final String rawPassword = "SecurePassword123!";

    @BeforeEach
    void setUp() {
        authenticateUserService = new AuthenticateUserService(
                userRepositoryPort,
                refreshTokenRepositoryPort,
                passwordEncoderPort,
                tokenSignerPort,
                5,
                Duration.ofMinutes(15),
                DirectUnitOfWork.INSTANCE
        );

        tenantId = TenantId.generate();
        Email email = Email.of("admin@taller.pe");
        PasswordHash passwordHash = PasswordHash.of("$2a$12$hashedPasswordExample");
        Role role = Role.create(RoleCode.ADMIN_TALLER, "Administrador");

        sampleUser = User.create(tenantId, email, passwordHash, "Admin General", Set.of(role));
    }

    @Test
    @DisplayName("Debe autenticar exitosamente y retornar Access Token y Refresh Token")
    void shouldAuthenticateSuccessfully() {
        LoginCommand command = new LoginCommand("admin@taller.pe", rawPassword, tenantId.getValue());

        when(userRepositoryPort.findByEmailAndTenantId(Email.of("admin@taller.pe"), tenantId)).thenReturn(Optional.of(sampleUser));
        when(passwordEncoderPort.matches(rawPassword, sampleUser.getPasswordHash().getValue())).thenReturn(true);
        when(tokenSignerPort.generateAccessToken(sampleUser)).thenReturn("eyJhbGciOiJSUzI1NiJ9.mockToken");
        when(tokenSignerPort.generateRefreshToken(any(User.class))).thenReturn("mockRefreshTokenRaw");
        when(tokenSignerPort.extractTokenId(anyString())).thenReturn("token-id-de-prueba");
        when(tokenSignerPort.hashToken("mockRefreshTokenRaw")).thenReturn("hashedRefreshToken");
        when(tokenSignerPort.getAccessTokenDuration()).thenReturn(Duration.ofMinutes(15));
        when(tokenSignerPort.getRefreshTokenDuration()).thenReturn(Duration.ofDays(7));

        AuthResult result = authenticateUserService.authenticate(command);

        assertNotNull(result);
        assertEquals("eyJhbGciOiJSUzI1NiJ9.mockToken", result.accessToken());
        assertEquals("mockRefreshTokenRaw", result.refreshToken());
        assertEquals("Bearer", result.tokenType());
        assertEquals(sampleUser.getEmail().getValue(), result.email());
        assertTrue(result.roles().contains("ADMIN_TALLER"));

        verify(userRepositoryPort, times(1)).save(sampleUser);
        verify(refreshTokenRepositoryPort, times(1)).save(any(RefreshToken.class));
    }

    @Test
    @DisplayName("Debe incrementar intentos fallidos y lanzar InvalidCredentialsException con password incorrecto")
    void shouldFailAndIncrementAttemptsOnWrongPassword() {
        LoginCommand command = new LoginCommand("admin@taller.pe", "WrongPassword", tenantId.getValue());

        when(userRepositoryPort.findByEmailAndTenantId(Email.of("admin@taller.pe"), tenantId)).thenReturn(Optional.of(sampleUser));
        when(passwordEncoderPort.matches("WrongPassword", sampleUser.getPasswordHash().getValue())).thenReturn(false);

        assertThrows(InvalidCredentialsException.class, () -> authenticateUserService.authenticate(command));
        assertEquals(1, sampleUser.getFailedAttempts());
        verify(userRepositoryPort, times(1)).save(sampleUser);
    }

    @Test
    @DisplayName("Debe lanzar AccountLockedException cuando la cuenta está bloqueada")
    void shouldThrowAccountLockedWhenAlreadyLocked() {
        sampleUser.recordFailedAttempt(1, Duration.ofMinutes(15));
        LoginCommand command = new LoginCommand("admin@taller.pe", rawPassword, tenantId.getValue());

        when(userRepositoryPort.findByEmailAndTenantId(Email.of("admin@taller.pe"), tenantId)).thenReturn(Optional.of(sampleUser));

        assertThrows(AccountLockedException.class, () -> authenticateUserService.authenticate(command));
        verify(passwordEncoderPort, never()).matches(any(), any());
    }
}
