package com.erp.auth.application.service;

import com.erp.auth.application.dto.command.LoginCommand;
import com.erp.auth.application.dto.result.AuthResult;
import com.erp.auth.application.usecase.AuthenticateUserUseCase;
import com.erp.auth.domain.exception.AccountLockedException;
import com.erp.auth.domain.exception.InvalidCredentialsException;
import com.erp.auth.domain.model.RefreshToken;
import com.erp.auth.domain.model.User;
import com.erp.auth.domain.port.PasswordEncoderPort;
import com.erp.auth.domain.port.RefreshTokenRepositoryPort;
import com.erp.auth.domain.port.TokenSignerPort;
import com.erp.auth.domain.port.UserRepositoryPort;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.domain.valueobject.TenantId;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

public class AuthenticateUserService implements AuthenticateUserUseCase {

    private final UserRepositoryPort userRepositoryPort;
    private final RefreshTokenRepositoryPort refreshTokenRepositoryPort;
    private final PasswordEncoderPort passwordEncoderPort;
    private final TokenSignerPort tokenSignerPort;
    private final int maxFailedAttempts;
    private final Duration lockDuration;

    public AuthenticateUserService(
            UserRepositoryPort userRepositoryPort,
            RefreshTokenRepositoryPort refreshTokenRepositoryPort,
            PasswordEncoderPort passwordEncoderPort,
            TokenSignerPort tokenSignerPort,
            int maxFailedAttempts,
            Duration lockDuration) {
        this.userRepositoryPort = userRepositoryPort;
        this.refreshTokenRepositoryPort = refreshTokenRepositoryPort;
        this.passwordEncoderPort = passwordEncoderPort;
        this.tokenSignerPort = tokenSignerPort;
        this.maxFailedAttempts = maxFailedAttempts;
        this.lockDuration = lockDuration;
    }

    @Override
    public AuthResult authenticate(LoginCommand command) {
        if (command.email() == null || command.password() == null) {
            throw new InvalidCredentialsException("Correo y contraseña son obligatorios");
        }

        Email email = Email.of(command.email());
        Optional<User> userOpt;

        if (command.tenantId() != null) {
            userOpt = userRepositoryPort.findByEmailAndTenantId(email, new TenantId(command.tenantId()));
        } else {
            userOpt = userRepositoryPort.findByEmail(email);
        }

        if (userOpt.isEmpty()) {
            throw new InvalidCredentialsException();
        }

        User user = userOpt.get();

        // Verificar si la cuenta está bloqueada por intentos fallidos (QA-5)
        if (user.isAccountLocked()) {
            throw new AccountLockedException(user.getLockedUntil());
        }

        // Validar contraseña
        boolean passwordMatches = passwordEncoderPort.matches(command.password(), user.getPasswordHash().getValue());

        if (!passwordMatches) {
            user.recordFailedAttempt(maxFailedAttempts, lockDuration);
            userRepositoryPort.save(user);

            if (user.isAccountLocked()) {
                throw new AccountLockedException(user.getLockedUntil());
            }
            throw new InvalidCredentialsException();
        }

        // Login exitoso: restablecer intentos fallidos
        user.recordSuccessfulLogin();
        userRepositoryPort.save(user);

        // Generar Access Token (JWT firmado con RS256, 15 min)
        String accessToken = tokenSignerPort.generateAccessToken(user);

        // Generar Refresh Token con hash criptográfico
        String rawRefreshToken = tokenSignerPort.generateRandomTokenString();
        String refreshTokenHash = tokenSignerPort.hashToken(rawRefreshToken);
        Instant refreshTokenExpiry = Instant.now().plus(tokenSignerPort.getRefreshTokenDuration());

        RefreshToken refreshTokenEntity = RefreshToken.create(user.getId(), refreshTokenHash, refreshTokenExpiry);
        refreshTokenRepositoryPort.save(refreshTokenEntity);

        Set<String> roleCodes = user.getRoles().stream()
                .map(r -> r.getCode().name())
                .collect(Collectors.toSet());

        return new AuthResult(
                accessToken,
                rawRefreshToken,
                "Bearer",
                tokenSignerPort.getAccessTokenDuration().toSeconds(),
                user.getId(),
                user.getTenantId().getValue(),
                user.getEmail().getValue(),
                user.getFullName(),
                roleCodes
        );
    }
}
