package com.erp.auth.application.service;

import com.erp.auth.application.dto.command.RefreshTokenCommand;
import com.erp.auth.application.dto.result.AuthResult;
import com.erp.auth.application.usecase.RefreshTokenUseCase;
import com.erp.auth.application.usecase.RevokeTokenUseCase;
import com.erp.auth.domain.exception.AccountLockedException;
import com.erp.auth.domain.exception.InvalidTokenException;
import com.erp.auth.domain.exception.TokenExpiredException;
import com.erp.auth.domain.exception.TokenRevokedException;
import com.erp.auth.domain.exception.UserNotFoundException;
import com.erp.auth.domain.model.RefreshToken;
import com.erp.auth.domain.model.User;
import com.erp.auth.domain.port.RefreshTokenRepositoryPort;
import com.erp.auth.domain.port.TokenSignerPort;
import com.erp.auth.domain.port.UserRepositoryPort;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

public class RefreshTokenService implements RefreshTokenUseCase, RevokeTokenUseCase {

    private final RefreshTokenRepositoryPort refreshTokenRepositoryPort;
    private final UserRepositoryPort userRepositoryPort;
    private final TokenSignerPort tokenSignerPort;

    public RefreshTokenService(
            RefreshTokenRepositoryPort refreshTokenRepositoryPort,
            UserRepositoryPort userRepositoryPort,
            TokenSignerPort tokenSignerPort) {
        this.refreshTokenRepositoryPort = refreshTokenRepositoryPort;
        this.userRepositoryPort = userRepositoryPort;
        this.tokenSignerPort = tokenSignerPort;
    }

    @Override
    public AuthResult refreshToken(RefreshTokenCommand command) {
        if (command.refreshToken() == null || command.refreshToken().trim().isEmpty()) {
            throw new InvalidTokenException("El token de actualización es obligatorio");
        }

        String tokenHash = tokenSignerPort.hashToken(command.refreshToken().trim());
        Optional<RefreshToken> tokenOpt = refreshTokenRepositoryPort.findByTokenHash(tokenHash);

        if (tokenOpt.isEmpty()) {
            throw new InvalidTokenException("Token de actualización no encontrado");
        }

        RefreshToken token = tokenOpt.get();

        if (token.isRevoked()) {
            throw new TokenRevokedException();
        }

        if (Instant.now().isAfter(token.getExpiresAt())) {
            throw new TokenExpiredException();
        }

        // Rotación estricta: revocar token anterior
        token.revoke();
        refreshTokenRepositoryPort.save(token);

        User user = userRepositoryPort.findById(token.getUserId())
                .orElseThrow(() -> new UserNotFoundException(token.getUserId().toString()));

        if (user.isAccountLocked()) {
            throw new AccountLockedException(user.getLockedUntil());
        }

        // Generar nuevo Access Token y nuevo Refresh Token
        String newAccessToken = tokenSignerPort.generateAccessToken(user);
        String newRawRefreshToken = tokenSignerPort.generateRandomTokenString();
        String newRefreshTokenHash = tokenSignerPort.hashToken(newRawRefreshToken);
        Instant newRefreshTokenExpiry = Instant.now().plus(tokenSignerPort.getRefreshTokenDuration());

        RefreshToken newRefreshTokenEntity = RefreshToken.create(user.getId(), newRefreshTokenHash, newRefreshTokenExpiry);
        refreshTokenRepositoryPort.save(newRefreshTokenEntity);

        Set<String> roleCodes = user.getRoles().stream()
                .map(r -> r.getCode().name())
                .collect(Collectors.toSet());

        return new AuthResult(
                newAccessToken,
                newRawRefreshToken,
                "Bearer",
                tokenSignerPort.getAccessTokenDuration().toSeconds(),
                user.getId(),
                user.getTenantId().getValue(),
                user.getEmail().getValue(),
                user.getFullName(),
                roleCodes
        );
    }

    @Override
    public void revokeToken(String refreshToken) {
        if (refreshToken != null && !refreshToken.trim().isEmpty()) {
            String tokenHash = tokenSignerPort.hashToken(refreshToken.trim());
            refreshTokenRepositoryPort.revokeByTokenHash(tokenHash);
        }
    }

    @Override
    public void revokeAllUserTokens(UUID userId) {
        if (userId != null) {
            refreshTokenRepositoryPort.revokeAllByUserId(userId);
        }
    }
}
