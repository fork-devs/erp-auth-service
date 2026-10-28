package com.erp.auth.application.service;

import com.erp.auth.application.dto.command.LoginCommand;
import com.erp.auth.application.dto.result.AuthResult;
import com.erp.auth.application.usecase.AuthenticateUserUseCase;
import com.erp.auth.domain.exception.AccountLockedException;
import com.erp.auth.application.logging.AuthEventLogger;
import com.erp.auth.domain.exception.InvalidCredentialsException;
import com.erp.auth.domain.model.RefreshToken;
import com.erp.auth.domain.model.User;
import com.erp.auth.domain.port.PasswordEncoderPort;
import com.erp.auth.domain.port.RefreshTokenRepositoryPort;
import com.erp.auth.domain.exception.InvalidSecondFactorCodeException;
import com.erp.auth.domain.port.SecondFactorPort;
import com.erp.auth.domain.port.SecondFactorRepositoryPort;
import com.erp.auth.domain.port.TokenSignerPort;
import com.erp.auth.domain.port.UnitOfWork;
import com.erp.auth.domain.port.UserRepositoryPort;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.domain.valueobject.TenantId;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.Set;
import java.util.stream.Collectors;

public class AuthenticateUserService implements AuthenticateUserUseCase {

    /**
     * Dummy password hash not corresponding to any real account. Used to equalize
     * response latency when an account does not exist: verifying against it consumes
     * equivalent hashing time and prevents account enumeration via timing attacks.
     */
    private static final String HASH_SENUELO =
            "$2a$12$RAmvlO5s9LG2urup52BBsuDqh0/WakqD.ufHw41ey9CHK10OyvEb2";

    private final UserRepositoryPort userRepositoryPort;
    private final RefreshTokenRepositoryPort refreshTokenRepositoryPort;
    private final PasswordEncoderPort passwordEncoderPort;
    private final TokenSignerPort tokenSignerPort;
    private final int maxFailedAttempts;
    private final Duration lockDuration;
    private final SecondFactorPort secondFactorPort;
    private final SecondFactorRepositoryPort secondFactorRepositoryPort;
    private final UnitOfWork unitOfWork;

    public AuthenticateUserService(
            UserRepositoryPort userRepositoryPort,
            RefreshTokenRepositoryPort refreshTokenRepositoryPort,
            PasswordEncoderPort passwordEncoderPort,
            TokenSignerPort tokenSignerPort,
            int maxFailedAttempts,
            Duration lockDuration,
            SecondFactorPort secondFactorPort,
            SecondFactorRepositoryPort secondFactorRepositoryPort,
            UnitOfWork unitOfWork) {
        this.userRepositoryPort = userRepositoryPort;
        this.refreshTokenRepositoryPort = refreshTokenRepositoryPort;
        this.passwordEncoderPort = passwordEncoderPort;
        this.tokenSignerPort = tokenSignerPort;
        this.maxFailedAttempts = maxFailedAttempts;
        this.lockDuration = lockDuration;
        this.secondFactorPort = secondFactorPort;
        this.secondFactorRepositoryPort = secondFactorRepositoryPort;
        this.unitOfWork = unitOfWork;
    }

    /**
     * Determines whether the account is currently locked following the latest attempt.
     *
     * <p>Queries the database directly rather than reading from the in-memory domain model:
     * the failed attempts counter was incremented via an atomic database query, ensuring
     * the retrieved state reflects concurrent updates.
     */
    private boolean cuentaBloqueada(UUID userId, TenantId tenantId) {
        return userRepositoryPort.findByIdAndTenantId(userId, tenantId)
                .map(User::isAccountLocked)
                .orElse(false);
    }

    /**
     * Verifies the submitted second-factor authentication code.
     *
     * <p>The code is accepted if it matches the enrolled secret AND has not been used before.
     * A TOTP code is valid for its interval and the subsequent window; tracking the last accepted
     * counter prevents replay attacks within the validity window.
     */
    private boolean segundoFactorValido(User user, String codigo) {
        if (codigo == null || codigo.isBlank()) {
            return false;
        }

        String secreto = secondFactorRepositoryPort.findSecret(user.getId()).orElse(null);
        if (secreto == null) {
            return false;
        }

        Optional<Long> contador = secondFactorPort.verify(secreto, codigo, Instant.now());
        if (contador.isEmpty()) {
            return false;
        }

        Long ultimo = secondFactorRepositoryPort.findLastAcceptedCounter(user.getId()).orElse(-1L);
        if (contador.get() <= ultimo) {
            // The code was already used.
            return false;
        }

        unitOfWork.runInTransaction(() ->
                secondFactorRepositoryPort.recordAcceptedCounter(user.getId(), contador.get()));
        return true;
    }

    @Override
    public AuthResult authenticate(LoginCommand command) {
        if (command.email() == null || command.password() == null) {
            throw new InvalidCredentialsException("Correo y contraseña son obligatorios");
        }

        if (command.tenantId() == null) {
            throw new InvalidCredentialsException("El identificador de taller es obligatorio para iniciar sesion");
        }

        Email email = Email.of(command.email());
        Optional<User> userOpt = userRepositoryPort.findByEmailAndTenantId(email, new TenantId(command.tenantId()));

        if (userOpt.isEmpty()) {
            // When the account does not exist, check the password against a dummy hash.
            // Without this check, response time differences would reveal whether an account exists:
            // missing accounts would return immediately while existing accounts incur BCrypt work.
            // Equalizing the execution time prevents account enumeration.
            passwordEncoderPort.matches(command.password(), HASH_SENUELO);
            AuthEventLogger.registrar("login_fallido", command.tenantId(), null, null, "fallo",
                    Map.of("motivo", "cuenta_inexistente"));
            throw new InvalidCredentialsException();
        }

        User user = userOpt.get();

        // Always verify the password before rejecting the request for any reason.
        // If the account is locked and rejected early without verifying, response times
        // would reveal account state: an attacker could distinguish "locked" from "nonexistent".
        boolean passwordMatches = passwordEncoderPort.matches(command.password(), user.getPasswordHash().getValue());

        // Verify whether the account is locked due to failed attempts (QA-5)
        if (user.isAccountLocked()) {
            throw new AccountLockedException(user.getLockedUntil());
        }

        if (!passwordMatches) {
            // Failed attempts are committed in their OWN transaction. They cannot share
            // the login transaction boundary: failed authentication throws an exception,
            // which would roll back the attempt counter and prevent accounts from ever locking.
            //
            // The increment is ATOMIC in the database: concurrent attempts do not overwrite
            // each other's increments, avoiding lost updates common in read-modify-write patterns.
            unitOfWork.runInTransaction(() -> userRepositoryPort.incrementFailedAttempts(
                    user.getId(), maxFailedAttempts, lockDuration));

            if (cuentaBloqueada(user.getId(), new TenantId(command.tenantId()))) {
                AuthEventLogger.registrar("cuenta_bloqueada", command.tenantId(), user.getId(), null, "fallo",
                        Map.of());
                throw new AccountLockedException(user.getLockedUntil());
            }
            AuthEventLogger.registrar("login_fallido", command.tenantId(), user.getId(), null, "fallo",
                    Map.of("motivo", "credenciales_incorrectas"));
            throw new InvalidCredentialsException();
        }

        // When 2FA is enabled, credentials are not issued without a valid code.
        // An invalid code is treated as an authentication failure and counts toward lockout.
        if (user.isMfaEnabled() && !segundoFactorValido(user, command.secondFactorCode())) {
            user.recordFailedAttempt(maxFailedAttempts, lockDuration);
            unitOfWork.runInTransaction(() -> userRepositoryPort.save(user));

            if (user.isAccountLocked()) {
                throw new AccountLockedException(user.getLockedUntil());
            }
            throw new InvalidSecondFactorCodeException();
        }

        // Successful login is committed as a single atomic operation: resetting the
        // attempt counter and issuing the refresh token occur together within one transaction.
        AuthEventLogger.registrar("login_correcto", command.tenantId(), user.getId(), null, "ok", Map.of());
        return unitOfWork.callInTransaction(() -> {
            // Successful login: reset failed attempts counter
            user.recordSuccessfulLogin();
            userRepositoryPort.save(user);

            // Generate Access Token (RS256-signed JWT, 15 min)
            String accessToken = tokenSignerPort.generateAccessToken(user);

            // Generate Refresh Token with cryptographic hash
            String rawRefreshToken = tokenSignerPort.generateRefreshToken(user);
            String refreshTokenHash = tokenSignerPort.hashToken(rawRefreshToken);
            Instant refreshTokenExpiry = Instant.now().plus(tokenSignerPort.getRefreshTokenDuration());

            RefreshToken refreshTokenEntity = RefreshToken.create(user.getId(), user.getTenantId().getValue(),
                    refreshTokenHash, refreshTokenExpiry);
            refreshTokenRepositoryPort.save(refreshTokenEntity);

            Set<String> roleCodes = user.getRoles().stream()
                    .map(r -> r.getCode().name())
                    .collect(Collectors.toSet());

            return new AuthResult(
                    accessToken,
                    tokenSignerPort.extractTokenId(accessToken),
                    rawRefreshToken,
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
}
