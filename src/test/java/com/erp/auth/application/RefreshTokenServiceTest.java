package com.erp.auth.application;

import com.erp.auth.application.dto.command.RefreshTokenCommand;
import com.erp.auth.application.dto.result.AuthResult;
import com.erp.auth.application.service.RefreshTokenService;
import com.erp.auth.domain.exception.TokenExpiredException;
import com.erp.auth.domain.exception.TokenRevokedException;
import com.erp.auth.domain.model.RefreshToken;
import com.erp.auth.domain.model.Role;
import com.erp.auth.domain.model.RoleCode;
import com.erp.auth.domain.model.User;
import com.erp.auth.domain.port.RefreshTokenRepositoryPort;
import com.erp.auth.domain.port.TokenSignerPort;
import com.erp.auth.domain.port.UserRepositoryPort;
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
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RefreshTokenServiceTest {

    @Mock
    private RefreshTokenRepositoryPort refreshTokenRepositoryPort;

    @Mock
    private UserRepositoryPort userRepositoryPort;

    @Mock
    private TokenSignerPort tokenSignerPort;

    private RefreshTokenService refreshTokenService;
    private TenantId tenantId;
    private User sampleUser;
    private RefreshToken activeToken;
    private final String rawToken = "sampleRawRefreshToken";
    private final String tokenHash = "hashedSampleToken";

    @BeforeEach
    void setUp() {
        refreshTokenService = new RefreshTokenService(
                refreshTokenRepositoryPort,
                userRepositoryPort,
                tokenSignerPort
        );

        tenantId = TenantId.generate();
        Email email = Email.of("asesor@taller.pe");
        PasswordHash passwordHash = PasswordHash.of("$2a$12$hashedPasswordExample");
        Role role = Role.create(RoleCode.ASESOR, "Asesor");

        sampleUser = User.create(tenantId, email, passwordHash, "Juan Asesor", Set.of(role));
        activeToken = RefreshToken.create(sampleUser.getId(), tenantId.getValue(), tokenHash, Instant.now().plus(Duration.ofDays(7)));
    }

    @Test
    @DisplayName("Debe rotar el refresh token: revocar el anterior y emitir un nuevo par de tokens")
    void shouldRotateRefreshTokenSuccessfully() {
        RefreshTokenCommand command = new RefreshTokenCommand(rawToken, tenantId.getValue());

        when(tokenSignerPort.hashToken(rawToken)).thenReturn(tokenHash);
        when(refreshTokenRepositoryPort.findByTokenHashAndTenantId(tokenHash, tenantId.getValue())).thenReturn(Optional.of(activeToken));
        when(userRepositoryPort.findById(sampleUser.getId())).thenReturn(Optional.of(sampleUser));
        when(tokenSignerPort.generateAccessToken(sampleUser)).thenReturn("newSignedJwtToken");
        when(tokenSignerPort.generateRandomTokenString()).thenReturn("newRawRefreshToken");
        when(tokenSignerPort.hashToken("newRawRefreshToken")).thenReturn("newHashedRefreshToken");
        when(tokenSignerPort.getAccessTokenDuration()).thenReturn(Duration.ofMinutes(15));
        when(tokenSignerPort.getRefreshTokenDuration()).thenReturn(Duration.ofDays(7));

        AuthResult result = refreshTokenService.refreshToken(command);

        assertNotNull(result);
        assertEquals("newSignedJwtToken", result.accessToken());
        assertEquals("newRawRefreshToken", result.refreshToken());
        assertTrue(activeToken.isRevoked(), "El token anterior debe quedar revocado tras su uso");

        verify(refreshTokenRepositoryPort, times(2)).save(any(RefreshToken.class));
    }

    @Test
    @DisplayName("Debe lanzar TokenRevokedException al intentar usar un refresh token ya revocado")
    void shouldThrowTokenRevokedWhenReusingToken() {
        activeToken.revoke();
        RefreshTokenCommand command = new RefreshTokenCommand(rawToken, tenantId.getValue());

        when(tokenSignerPort.hashToken(rawToken)).thenReturn(tokenHash);
        when(refreshTokenRepositoryPort.findByTokenHashAndTenantId(tokenHash, tenantId.getValue())).thenReturn(Optional.of(activeToken));

        assertThrows(TokenRevokedException.class, () -> refreshTokenService.refreshToken(command));
    }

    @Test
    @DisplayName("Debe lanzar TokenExpiredException si el refresh token ha expirado")
    void shouldThrowTokenExpiredWhenTokenIsPastExpiry() {
        RefreshToken expiredToken = new RefreshToken(
                UUID.randomUUID(),
                sampleUser.getId(),
                tenantId.getValue(),
                tokenHash,
                Instant.now().minus(Duration.ofDays(1)),
                false,
                Instant.now().minus(Duration.ofDays(8))
        );

        RefreshTokenCommand command = new RefreshTokenCommand(rawToken, tenantId.getValue());

        when(tokenSignerPort.hashToken(rawToken)).thenReturn(tokenHash);
        when(refreshTokenRepositoryPort.findByTokenHashAndTenantId(tokenHash, tenantId.getValue())).thenReturn(Optional.of(expiredToken));

        assertThrows(TokenExpiredException.class, () -> refreshTokenService.refreshToken(command));
    }
}
