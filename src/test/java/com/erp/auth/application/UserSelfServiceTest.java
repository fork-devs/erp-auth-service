package com.erp.auth.application;

import com.erp.auth.application.dto.command.UpdateUserEmailCommand;
import com.erp.auth.application.dto.command.UpdateUserPasswordCommand;
import com.erp.auth.application.dto.result.AuthResult;
import com.erp.auth.application.dto.result.UserResult;
import com.erp.auth.application.service.UserSelfService;
import com.erp.auth.domain.exception.InvalidCredentialsException;
import com.erp.auth.domain.exception.UserAlreadyExistsException;
import com.erp.auth.domain.exception.UserNotFoundException;
import com.erp.auth.domain.exception.WeakPasswordException;
import com.erp.auth.domain.model.PasswordPolicy;
import com.erp.auth.domain.model.Role;
import com.erp.auth.domain.model.RoleCode;
import com.erp.auth.domain.model.User;
import com.erp.auth.domain.port.PasswordEncoderPort;
import com.erp.auth.domain.port.RefreshTokenRepositoryPort;
import com.erp.auth.domain.port.TokenSignerPort;
import com.erp.auth.domain.port.UserRepositoryPort;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.domain.valueobject.PasswordHash;
import com.erp.auth.domain.valueobject.TenantId;
import com.erp.auth.support.DirectUnitOfWork;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Duration;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserSelfServiceTest {

    @Mock
    private UserRepositoryPort userRepositoryPort;
    @Mock
    private RefreshTokenRepositoryPort refreshTokenRepositoryPort;
    @Mock
    private PasswordEncoderPort passwordEncoderPort;
    @Mock
    private TokenSignerPort tokenSignerPort;

    private UserSelfService userSelfService;
    private final PasswordPolicy passwordPolicy = new PasswordPolicy(8);

    @BeforeEach
    void setUp() {
        userSelfService = new UserSelfService(
                userRepositoryPort,
                refreshTokenRepositoryPort,
                passwordEncoderPort,
                tokenSignerPort,
                passwordPolicy,
                DirectUnitOfWork.INSTANCE
        );
    }

    @Test
    @DisplayName("GIVEN existing userId WHEN getUserById THEN returns profile")
    void testGetUserByIdSuccess() {
        UUID userId = UUID.randomUUID();
        User user = User.create(
                new TenantId(UUID.randomUUID()),
                new Email("profile@example.com"),
                new PasswordHash("hash"),
                "User Name",
                Set.of(new Role(UUID.randomUUID(), RoleCode.TECHNICIAN, "Tech"))
        );
        when(userRepositoryPort.findById(userId)).thenReturn(Optional.of(user));

        UserResult result = userSelfService.getUserById(userId);

        assertThat(result).isNotNull();
        assertThat(result.email()).isEqualTo("profile@example.com");
        assertThat(result.fullName()).isEqualTo("User Name");
    }

    @Test
    @DisplayName("GIVEN non-existing userId WHEN getUserById THEN throws UserNotFoundException")
    void testGetUserByIdNotFound() {
        UUID userId = UUID.randomUUID();
        when(userRepositoryPort.findById(userId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> userSelfService.getUserById(userId))
                .isInstanceOf(UserNotFoundException.class);
    }

    @Test
    @DisplayName("GIVEN valid new email WHEN updateEmail THEN revokes old tokens and returns new ones")
    void testUpdateEmailSuccess() {
        UUID userId = UUID.randomUUID();
        User user = User.create(
                new TenantId(UUID.randomUUID()),
                new Email("old@example.com"),
                new PasswordHash("hash"),
                "User Name",
                Set.of(new Role(UUID.randomUUID(), RoleCode.CUSTOMER, "Customer"))
        );
        when(userRepositoryPort.findById(userId)).thenReturn(Optional.of(user));
        when(userRepositoryPort.existsByEmailAndTenantId(new Email("new@example.com"), user.getTenantId()))
                .thenReturn(false);
        when(userRepositoryPort.save(any(User.class))).thenReturn(user);

        when(tokenSignerPort.generateAccessToken(any(User.class))).thenReturn("new-access-token");
        when(tokenSignerPort.extractTokenId("new-access-token")).thenReturn("token-id-456");
        when(tokenSignerPort.generateRefreshToken(any(User.class))).thenReturn("new-refresh-token");
        when(tokenSignerPort.hashToken("new-refresh-token")).thenReturn("new-refresh-hash");
        when(tokenSignerPort.getRefreshTokenDuration()).thenReturn(Duration.ofDays(7));
        when(tokenSignerPort.getAccessTokenDuration()).thenReturn(Duration.ofMinutes(15));

        AuthResult result = userSelfService.updateEmail(new UpdateUserEmailCommand(userId, "new@example.com"));

        assertThat(result).isNotNull();
        assertThat(result.accessToken()).isEqualTo("new-access-token");
        verify(refreshTokenRepositoryPort).revokeAllByUserId(user.getId());
        verify(userRepositoryPort).save(user);
    }

    @Test
    @DisplayName("GIVEN already used email WHEN updateEmail THEN throws UserAlreadyExistsException")
    void testUpdateEmailAlreadyInUse() {
        UUID userId = UUID.randomUUID();
        User user = User.create(
                new TenantId(UUID.randomUUID()),
                new Email("old@example.com"),
                new PasswordHash("hash"),
                "User Name",
                Set.of()
        );
        when(userRepositoryPort.findById(userId)).thenReturn(Optional.of(user));
        when(userRepositoryPort.existsByEmailAndTenantId(new Email("duplicate@example.com"), user.getTenantId()))
                .thenReturn(true);

        assertThatThrownBy(() -> userSelfService.updateEmail(new UpdateUserEmailCommand(userId, "duplicate@example.com")))
                .isInstanceOf(UserAlreadyExistsException.class);
    }

    @Test
    @DisplayName("GIVEN correct current password WHEN updatePassword THEN updates hash and revokes all tokens")
    void testUpdatePasswordSuccess() {
        UUID userId = UUID.randomUUID();
        User user = User.create(
                new TenantId(UUID.randomUUID()),
                new Email("user@example.com"),
                new PasswordHash("stored-hash"),
                "User Name",
                Set.of()
        );
        when(userRepositoryPort.findById(userId)).thenReturn(Optional.of(user));
        when(passwordEncoderPort.matches("CurrentPassword123!", "stored-hash")).thenReturn(true);
        when(passwordEncoderPort.encode("NewSecurePassword456!")).thenReturn("new-hash");

        userSelfService.updatePassword(new UpdateUserPasswordCommand(
                userId, "CurrentPassword123!", "NewSecurePassword456!"));

        verify(userRepositoryPort).save(user);
        verify(refreshTokenRepositoryPort).revokeAllByUserId(user.getId());
    }

    @Test
    @DisplayName("GIVEN wrong current password WHEN updatePassword THEN throws InvalidCredentialsException")
    void testUpdatePasswordWrongCurrent() {
        UUID userId = UUID.randomUUID();
        User user = User.create(
                new TenantId(UUID.randomUUID()),
                new Email("user@example.com"),
                new PasswordHash("stored-hash"),
                "User Name",
                Set.of()
        );
        when(userRepositoryPort.findById(userId)).thenReturn(Optional.of(user));
        when(passwordEncoderPort.matches("WrongPassword!", "stored-hash")).thenReturn(false);

        assertThatThrownBy(() -> userSelfService.updatePassword(new UpdateUserPasswordCommand(
                userId, "WrongPassword!", "NewSecurePassword456!")))
                .isInstanceOf(InvalidCredentialsException.class);
    }

    @Test
    @DisplayName("GIVEN weak new password WHEN updatePassword THEN throws WeakPasswordException")
    void testUpdatePasswordWeakPassword() {
        UUID userId = UUID.randomUUID();

        assertThatThrownBy(() -> userSelfService.updatePassword(new UpdateUserPasswordCommand(
                userId, "CurrentPassword123!", "short")))
                .isInstanceOf(WeakPasswordException.class);
    }
}
