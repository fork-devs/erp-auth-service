package com.erp.auth.application.service;

import com.erp.auth.application.dto.command.UpdateUserEmailCommand;
import com.erp.auth.application.dto.command.UpdateUserPasswordCommand;
import com.erp.auth.application.dto.result.AuthResult;
import com.erp.auth.application.dto.result.UserResult;
import com.erp.auth.application.usecase.GetUserByIdUseCase;
import com.erp.auth.application.usecase.UpdateUserEmailUseCase;
import com.erp.auth.application.usecase.UpdateUserPasswordUseCase;
import com.erp.auth.domain.exception.InvalidCredentialsException;
import com.erp.auth.domain.exception.UserAlreadyExistsException;
import com.erp.auth.domain.exception.UserNotFoundException;
import com.erp.auth.domain.exception.WeakPasswordException;
import com.erp.auth.domain.model.PasswordPolicy;
import com.erp.auth.domain.model.RefreshToken;
import com.erp.auth.domain.model.User;
import com.erp.auth.domain.port.PasswordEncoderPort;
import com.erp.auth.domain.port.RefreshTokenRepositoryPort;
import com.erp.auth.domain.port.TokenSignerPort;
import com.erp.auth.domain.port.UnitOfWork;
import com.erp.auth.domain.port.UserRepositoryPort;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.domain.valueobject.PasswordHash;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

public class UserSelfService implements GetUserByIdUseCase, UpdateUserEmailUseCase, UpdateUserPasswordUseCase {

    private final UserRepositoryPort userRepositoryPort;
    private final RefreshTokenRepositoryPort refreshTokenRepositoryPort;
    private final PasswordEncoderPort passwordEncoderPort;
    private final TokenSignerPort tokenSignerPort;
    private final PasswordPolicy passwordPolicy;
    private final UnitOfWork unitOfWork;

    public UserSelfService(
            UserRepositoryPort userRepositoryPort,
            RefreshTokenRepositoryPort refreshTokenRepositoryPort,
            PasswordEncoderPort passwordEncoderPort,
            TokenSignerPort tokenSignerPort,
            PasswordPolicy passwordPolicy,
            UnitOfWork unitOfWork) {
        this.userRepositoryPort = userRepositoryPort;
        this.refreshTokenRepositoryPort = refreshTokenRepositoryPort;
        this.passwordEncoderPort = passwordEncoderPort;
        this.tokenSignerPort = tokenSignerPort;
        this.passwordPolicy = passwordPolicy;
        this.unitOfWork = unitOfWork;
    }

    @Override
    public UserResult getUserById(UUID userId) {
        User user = userRepositoryPort.findById(userId)
                .orElseThrow(() -> new UserNotFoundException(userId.toString()));

        Set<String> roleNames = user.getRoles().stream()
                .map(r -> r.getCode().name())
                .collect(Collectors.toSet());

        return new UserResult(
                user.getId(),
                user.getTenantId().getValue(),
                user.getEmail().getValue(),
                user.getFullName(),
                user.isMfaEnabled(),
                roleNames,
                user.getCreatedAt()
        );
    }

    @Override
    public AuthResult updateEmail(UpdateUserEmailCommand command) {
        Email newEmail = new Email(command.newEmail());

        return unitOfWork.callInTransaction(() -> {
            User user = userRepositoryPort.findById(command.userId())
                    .orElseThrow(() -> new UserNotFoundException(command.userId().toString()));

            if (userRepositoryPort.existsByEmailAndTenantId(newEmail, user.getTenantId())) {
                throw new UserAlreadyExistsException("El correo ya está en uso: " + command.newEmail());
            }

            // Invalidate all previous refresh tokens
            refreshTokenRepositoryPort.revokeAllByUserId(user.getId());

            user.changeEmail(newEmail);
            user = userRepositoryPort.save(user);

            // Issue new session tokens with updated email
            String accessToken = tokenSignerPort.generateAccessToken(user);
            String rawRefreshToken = tokenSignerPort.generateRefreshToken(user);
            String refreshTokenHash = tokenSignerPort.hashToken(rawRefreshToken);
            Instant refreshTokenExpiry = Instant.now().plus(tokenSignerPort.getRefreshTokenDuration());

            RefreshToken refreshTokenEntity = RefreshToken.create(
                    user.getId(),
                    user.getTenantId().getValue(),
                    refreshTokenHash,
                    refreshTokenExpiry
            );
            refreshTokenRepositoryPort.save(refreshTokenEntity);

            Set<String> roleNames = user.getRoles().stream()
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
                    roleNames
            );
        });
    }

    @Override
    public void updatePassword(UpdateUserPasswordCommand command) {
        Optional<String> rejectReason = passwordPolicy.reject(command.newPassword());
        if (rejectReason.isPresent()) {
            throw new WeakPasswordException(rejectReason.get());
        }

        unitOfWork.runInTransaction(() -> {
            User user = userRepositoryPort.findById(command.userId())
                    .orElseThrow(() -> new UserNotFoundException(command.userId().toString()));

            if (!passwordEncoderPort.matches(command.currentPassword(), user.getPasswordHash().getValue())) {
                throw new InvalidCredentialsException("Contraseña actual incorrecta");
            }

            PasswordHash newHash = new PasswordHash(passwordEncoderPort.encode(command.newPassword()));
            user.changePassword(newHash);
            userRepositoryPort.save(user);

            // Invalidate all existing sessions globally
            refreshTokenRepositoryPort.revokeAllByUserId(user.getId());
        });
    }
}
