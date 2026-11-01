package com.erp.auth.application.service;

import com.erp.auth.application.dto.command.GoogleLoginCommand;
import com.erp.auth.application.dto.result.AuthResult;
import com.erp.auth.application.usecase.GoogleLoginUseCase;
import com.erp.auth.domain.model.GoogleTokenPayload;
import com.erp.auth.domain.model.RefreshToken;
import com.erp.auth.domain.model.Role;
import com.erp.auth.domain.model.RoleCode;
import com.erp.auth.domain.model.User;
import com.erp.auth.domain.port.GoogleTokenVerifierPort;
import com.erp.auth.domain.port.PasswordEncoderPort;
import com.erp.auth.domain.port.RefreshTokenRepositoryPort;
import com.erp.auth.domain.port.RoleRepositoryPort;
import com.erp.auth.domain.port.TokenSignerPort;
import com.erp.auth.domain.port.UnitOfWork;
import com.erp.auth.domain.port.UserRepositoryPort;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.domain.valueobject.PasswordHash;
import com.erp.auth.domain.valueobject.TenantId;

import java.time.Instant;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

public class GoogleAuthenticationService implements GoogleLoginUseCase {

    private static final UUID DEFAULT_PLATFORM_TENANT = UUID.fromString("00000000-0000-0000-0000-000000000000");

    private final GoogleTokenVerifierPort googleTokenVerifierPort;
    private final UserRepositoryPort userRepositoryPort;
    private final RoleRepositoryPort roleRepositoryPort;
    private final RefreshTokenRepositoryPort refreshTokenRepositoryPort;
    private final PasswordEncoderPort passwordEncoderPort;
    private final TokenSignerPort tokenSignerPort;
    private final UnitOfWork unitOfWork;

    public GoogleAuthenticationService(
            GoogleTokenVerifierPort googleTokenVerifierPort,
            UserRepositoryPort userRepositoryPort,
            RoleRepositoryPort roleRepositoryPort,
            RefreshTokenRepositoryPort refreshTokenRepositoryPort,
            PasswordEncoderPort passwordEncoderPort,
            TokenSignerPort tokenSignerPort,
            UnitOfWork unitOfWork) {
        this.googleTokenVerifierPort = googleTokenVerifierPort;
        this.userRepositoryPort = userRepositoryPort;
        this.roleRepositoryPort = roleRepositoryPort;
        this.refreshTokenRepositoryPort = refreshTokenRepositoryPort;
        this.passwordEncoderPort = passwordEncoderPort;
        this.tokenSignerPort = tokenSignerPort;
        this.unitOfWork = unitOfWork;
    }

    @Override
    public AuthResult loginWithGoogle(GoogleLoginCommand command) {
        GoogleTokenPayload payload = googleTokenVerifierPort.verifyToken(command.idToken());
        Email email = new Email(payload.email());

        return unitOfWork.callInTransaction(() -> {
            TenantId targetTenantId = command.tenantId() != null
                    ? new TenantId(command.tenantId())
                    : null;

            Optional<User> existingUser = targetTenantId != null
                    ? userRepositoryPort.findByEmailAndTenantId(email, targetTenantId)
                    : userRepositoryPort.findByEmail(email);

            User user;
            if (existingUser.isPresent()) {
                user = existingUser.get();
                if (payload.fullName() != null && !payload.fullName().isBlank()) {
                    user.updateFullName(payload.fullName());
                    user = userRepositoryPort.save(user);
                }
            } else {
                TenantId resolvedTenant = targetTenantId != null ? targetTenantId : new TenantId(DEFAULT_PLATFORM_TENANT);
                Set<Role> roles = new HashSet<>();
                roleRepositoryPort.findByCode(RoleCode.CUSTOMER).ifPresent(roles::add);

                PasswordHash randomHash = new PasswordHash(passwordEncoderPort.encode(UUID.randomUUID().toString()));
                user = User.create(resolvedTenant, email, randomHash, payload.fullName(), roles);
                user = userRepositoryPort.save(user);
            }

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
}
