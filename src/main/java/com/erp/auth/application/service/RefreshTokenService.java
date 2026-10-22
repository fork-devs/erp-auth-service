package com.erp.auth.application.service;

import com.erp.auth.application.dto.command.RefreshTokenCommand;
import com.erp.auth.application.logging.AuthEventLogger;
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
import com.erp.auth.domain.port.UnitOfWork;
import com.erp.auth.domain.port.UserRepositoryPort;
import com.erp.auth.domain.valueobject.TenantId;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

public class RefreshTokenService implements RefreshTokenUseCase, RevokeTokenUseCase {

    private final RefreshTokenRepositoryPort refreshTokenRepositoryPort;
    private final UserRepositoryPort userRepositoryPort;
    private final TokenSignerPort tokenSignerPort;
    private final UnitOfWork unitOfWork;

    public RefreshTokenService(
            RefreshTokenRepositoryPort refreshTokenRepositoryPort,
            UserRepositoryPort userRepositoryPort,
            TokenSignerPort tokenSignerPort,
            UnitOfWork unitOfWork) {
        this.refreshTokenRepositoryPort = refreshTokenRepositoryPort;
        this.userRepositoryPort = userRepositoryPort;
        this.tokenSignerPort = tokenSignerPort;
        this.unitOfWork = unitOfWork;
    }

    @Override
    public AuthResult refreshToken(RefreshTokenCommand command) {
        if (command.refreshToken() == null || command.refreshToken().trim().isEmpty()) {
            throw new InvalidTokenException("El token de actualización es obligatorio");
        }

        if (command.tenantId() == null) {
            throw new IllegalArgumentException("El identificador de taller es obligatorio para renovar el token");
        }

        String tokenHash = tokenSignerPort.hashToken(command.refreshToken().trim());
        Optional<RefreshToken> tokenOpt =
                refreshTokenRepositoryPort.findByTokenHashAndTenantId(tokenHash, command.tenantId());

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

        // La rotacion se confirma como una sola operacion. Antes, revocar el
        // token anterior y crear el nuevo eran dos escrituras en dos
        // transacciones: si la segunda fallaba, el usuario se quedaba sin
        // ningun token valido pese a haber iniciado sesion correctamente, y
        // el token anterior, ya revocado, no servia para volver a entrar.
        return unitOfWork.callInTransaction(() -> {
            // Rotacion estricta: revocar token anterior
            token.revoke();
            refreshTokenRepositoryPort.save(token);

            User user = userRepositoryPort.findByIdAndTenantId(token.getUserId(), new TenantId(token.getTenantId()))
                    .orElseThrow(() -> new UserNotFoundException(token.getUserId().toString()));

            if (user.isAccountLocked()) {
                throw new AccountLockedException(user.getLockedUntil());
            }

            // Generar nuevo Access Token y nuevo Refresh Token
            String newAccessToken = tokenSignerPort.generateAccessToken(user);
            String newRawRefreshToken = tokenSignerPort.generateRefreshToken(user);
            String newRefreshTokenHash = tokenSignerPort.hashToken(newRawRefreshToken);
            Instant newRefreshTokenExpiry = Instant.now().plus(tokenSignerPort.getRefreshTokenDuration());

            RefreshToken newRefreshTokenEntity = RefreshToken.create(user.getId(), user.getTenantId().getValue(),
                    newRefreshTokenHash, newRefreshTokenExpiry);
            refreshTokenRepositoryPort.save(newRefreshTokenEntity);

            Set<String> roleCodes = user.getRoles().stream()
                    .map(r -> r.getCode().name())
                    .collect(Collectors.toSet());

            AuthEventLogger.registrar("token_refresco_rotado", user.getTenantId().getValue(), user.getId(), null,
                    "ok", Map.of());
            return new AuthResult(
                    newAccessToken,
                    tokenSignerPort.extractTokenId(newAccessToken),
                    newRawRefreshToken,
                    "Bearer",
                    tokenSignerPort.getAccessTokenDuration().toSeconds(),
                    user.getId(),
                    user.getTenantId().getValue(),
                    user.getEmail().getValue(),
                    user.getFullName(),
                    roleCodes
            );
        });
    }

    @Override
    public void revokeToken(String refreshToken) {
        if (refreshToken != null && !refreshToken.trim().isEmpty()) {
            String tokenHash = tokenSignerPort.hashToken(refreshToken.trim());
            unitOfWork.runInTransaction(() -> refreshTokenRepositoryPort.revokeByTokenHash(tokenHash));
        }
    }

    @Override
    public void revokeAllUserTokens(UUID userId) {
        if (userId != null) {
            unitOfWork.runInTransaction(() -> refreshTokenRepositoryPort.revokeAllByUserId(userId));
        }
    }
}
