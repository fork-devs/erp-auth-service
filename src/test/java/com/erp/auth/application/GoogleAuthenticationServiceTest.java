package com.erp.auth.application;

import com.erp.auth.application.dto.command.GoogleLoginCommand;
import com.erp.auth.application.dto.result.AuthResult;
import com.erp.auth.application.service.GoogleAuthenticationService;
import com.erp.auth.domain.model.GoogleTokenPayload;
import com.erp.auth.domain.model.Role;
import com.erp.auth.domain.model.RoleCode;
import com.erp.auth.domain.model.User;
import com.erp.auth.domain.port.GoogleTokenVerifierPort;
import com.erp.auth.domain.port.PasswordEncoderPort;
import com.erp.auth.domain.port.RefreshTokenRepositoryPort;
import com.erp.auth.domain.port.RoleRepositoryPort;
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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class GoogleAuthenticationServiceTest {

    @Mock
    private GoogleTokenVerifierPort googleTokenVerifierPort;
    @Mock
    private UserRepositoryPort userRepositoryPort;
    @Mock
    private RoleRepositoryPort roleRepositoryPort;
    @Mock
    private RefreshTokenRepositoryPort refreshTokenRepositoryPort;
    @Mock
    private PasswordEncoderPort passwordEncoderPort;
    @Mock
    private TokenSignerPort tokenSignerPort;

    private GoogleAuthenticationService googleAuthService;

    @BeforeEach
    void setUp() {
        googleAuthService = new GoogleAuthenticationService(
                googleTokenVerifierPort,
                userRepositoryPort,
                roleRepositoryPort,
                refreshTokenRepositoryPort,
                passwordEncoderPort,
                tokenSignerPort,
                DirectUnitOfWork.INSTANCE
        );
    }

    @Test
    @DisplayName("GIVEN new google user WHEN loginWithGoogle THEN provisions user and returns tokens")
    void testNewGoogleUserProvisioning() {
        String token = "valid-google-id-token";
        GoogleTokenPayload payload = new GoogleTokenPayload("google.user@example.com", "Google User", "g-12345");
        when(googleTokenVerifierPort.verifyToken(token)).thenReturn(payload);
        when(userRepositoryPort.findByEmail(any(Email.class))).thenReturn(Optional.empty());

        Role customerRole = new Role(UUID.randomUUID(), RoleCode.CUSTOMER, "Customer Role");
        when(roleRepositoryPort.findByCode(RoleCode.CUSTOMER)).thenReturn(Optional.of(customerRole));
        when(passwordEncoderPort.encode(anyString())).thenReturn("encoded-random-pwd");

        when(userRepositoryPort.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(tokenSignerPort.generateAccessToken(any(User.class))).thenReturn("access-token-jwt");
        when(tokenSignerPort.extractTokenId("access-token-jwt")).thenReturn("token-id-123");
        when(tokenSignerPort.generateRefreshToken(any(User.class))).thenReturn("refresh-token-uuid");
        when(tokenSignerPort.hashToken("refresh-token-uuid")).thenReturn("refresh-token-hash");
        when(tokenSignerPort.getRefreshTokenDuration()).thenReturn(Duration.ofDays(7));
        when(tokenSignerPort.getAccessTokenDuration()).thenReturn(Duration.ofMinutes(15));

        AuthResult result = googleAuthService.loginWithGoogle(new GoogleLoginCommand(token, null));

        assertThat(result).isNotNull();
        assertThat(result.email()).isEqualTo("google.user@example.com");
        assertThat(result.accessToken()).isEqualTo("access-token-jwt");
        assertThat(result.refreshToken()).isEqualTo("refresh-token-uuid");
        verify(userRepositoryPort).save(any(User.class));
        verify(refreshTokenRepositoryPort).save(any());
    }

    @Test
    @DisplayName("GIVEN existing google user WHEN loginWithGoogle THEN authenticates and returns tokens")
    void testExistingGoogleUserLogin() {
        String token = "valid-google-id-token";
        GoogleTokenPayload payload = new GoogleTokenPayload("existing@example.com", "Updated Name", "g-67890");
        when(googleTokenVerifierPort.verifyToken(token)).thenReturn(payload);

        User existingUser = User.create(
                new TenantId(UUID.randomUUID()),
                new Email("existing@example.com"),
                new PasswordHash("existing-hash"),
                "Old Name",
                Set.of(new Role(UUID.randomUUID(), RoleCode.CUSTOMER, "Customer"))
        );
        when(userRepositoryPort.findByEmail(new Email("existing@example.com"))).thenReturn(Optional.of(existingUser));
        when(userRepositoryPort.save(any(User.class))).thenReturn(existingUser);

        when(tokenSignerPort.generateAccessToken(any(User.class))).thenReturn("access-token-jwt");
        when(tokenSignerPort.extractTokenId("access-token-jwt")).thenReturn("token-id-123");
        when(tokenSignerPort.generateRefreshToken(any(User.class))).thenReturn("refresh-token-uuid");
        when(tokenSignerPort.hashToken("refresh-token-uuid")).thenReturn("refresh-token-hash");
        when(tokenSignerPort.getRefreshTokenDuration()).thenReturn(Duration.ofDays(7));
        when(tokenSignerPort.getAccessTokenDuration()).thenReturn(Duration.ofMinutes(15));

        AuthResult result = googleAuthService.loginWithGoogle(new GoogleLoginCommand(token, null));

        assertThat(result).isNotNull();
        assertThat(result.fullName()).isEqualTo("Updated Name");
        verify(userRepositoryPort).save(existingUser);
    }
}
