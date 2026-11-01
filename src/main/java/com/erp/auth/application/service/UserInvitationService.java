package com.erp.auth.application.service;

import com.erp.auth.application.dto.command.AcceptInvitationCommand;
import com.erp.auth.application.dto.command.InviteUserCommand;
import com.erp.auth.application.dto.result.AuthResult;
import com.erp.auth.application.dto.result.InvitationDetailsResult;
import com.erp.auth.application.dto.result.InviteUserResult;
import com.erp.auth.application.usecase.AcceptInvitationUseCase;
import com.erp.auth.application.usecase.GetInvitationUseCase;
import com.erp.auth.application.usecase.InviteUserUseCase;
import com.erp.auth.domain.exception.InvalidTokenException;
import com.erp.auth.domain.exception.RoleNotAssignableException;
import com.erp.auth.domain.exception.TokenExpiredException;
import com.erp.auth.domain.exception.UserAlreadyExistsException;
import com.erp.auth.domain.exception.WeakPasswordException;
import com.erp.auth.domain.model.NotificationMessage;
import com.erp.auth.domain.model.PasswordPolicy;
import com.erp.auth.domain.model.RefreshToken;
import com.erp.auth.domain.model.Role;
import com.erp.auth.domain.model.RoleAssignmentPolicy;
import com.erp.auth.domain.model.RoleCode;
import com.erp.auth.domain.model.User;
import com.erp.auth.domain.model.UserInvitation;
import com.erp.auth.domain.port.NotificationPort;
import com.erp.auth.domain.port.PasswordEncoderPort;
import com.erp.auth.domain.port.RefreshTokenRepositoryPort;
import com.erp.auth.domain.port.RoleRepositoryPort;
import com.erp.auth.domain.port.TokenSignerPort;
import com.erp.auth.domain.port.UnitOfWork;
import com.erp.auth.domain.port.UserInvitationRepositoryPort;
import com.erp.auth.domain.port.UserRepositoryPort;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.domain.valueobject.PasswordHash;
import com.erp.auth.domain.valueobject.TenantId;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

public class UserInvitationService implements InviteUserUseCase, AcceptInvitationUseCase, GetInvitationUseCase {

    private static final Duration INVITATION_VALIDITY = Duration.ofHours(48);
    private static final String DEFAULT_INVITATION_URL = "https://app.driveos.pe/activar-cuenta";

    private final UserInvitationRepositoryPort invitationRepositoryPort;
    private final UserRepositoryPort userRepositoryPort;
    private final RoleRepositoryPort roleRepositoryPort;
    private final PasswordEncoderPort passwordEncoderPort;
    private final TokenSignerPort tokenSignerPort;
    private final RefreshTokenRepositoryPort refreshTokenRepositoryPort;
    private final NotificationPort notificationPort;
    private final PasswordPolicy passwordPolicy;
    private final UnitOfWork unitOfWork;
    private final String invitationBaseUrl;
    private final SecureRandom secureRandom = new SecureRandom();

    public UserInvitationService(UserInvitationRepositoryPort invitationRepositoryPort,
                                 UserRepositoryPort userRepositoryPort,
                                 RoleRepositoryPort roleRepositoryPort,
                                 PasswordEncoderPort passwordEncoderPort,
                                 TokenSignerPort tokenSignerPort,
                                 RefreshTokenRepositoryPort refreshTokenRepositoryPort,
                                 NotificationPort notificationPort,
                                 PasswordPolicy passwordPolicy,
                                 UnitOfWork unitOfWork,
                                 String invitationBaseUrl) {
        this.invitationRepositoryPort = Objects.requireNonNull(invitationRepositoryPort);
        this.userRepositoryPort = Objects.requireNonNull(userRepositoryPort);
        this.roleRepositoryPort = Objects.requireNonNull(roleRepositoryPort);
        this.passwordEncoderPort = Objects.requireNonNull(passwordEncoderPort);
        this.tokenSignerPort = Objects.requireNonNull(tokenSignerPort);
        this.refreshTokenRepositoryPort = Objects.requireNonNull(refreshTokenRepositoryPort);
        this.notificationPort = Objects.requireNonNull(notificationPort);
        this.passwordPolicy = Objects.requireNonNull(passwordPolicy);
        this.unitOfWork = Objects.requireNonNull(unitOfWork);
        this.invitationBaseUrl = (invitationBaseUrl != null && !invitationBaseUrl.isBlank())
                ? invitationBaseUrl.trim()
                : DEFAULT_INVITATION_URL;
    }

    @Override
    public InviteUserResult invite(InviteUserCommand command) {
        if (command.tenantId() == null || command.email() == null || command.role() == null) {
            throw new IllegalArgumentException("Tenant, email y rol son obligatorios");
        }

        Set<RoleCode> permitted = RoleAssignmentPolicy.assignableRolesFor(command.actorRole());
        if (!permitted.contains(command.role())) {
            throw new RoleNotAssignableException(command.actorRole(), command.role());
        }

        Email email = Email.of(command.email());
        TenantId tenantId = new TenantId(command.tenantId());

        if (userRepositoryPort.existsByEmailAndTenantId(email, tenantId)) {
            throw new UserAlreadyExistsException(email.getValue());
        }

        String rawToken = generateSecureToken();
        String tokenHash = tokenSignerPort.hashToken(rawToken);

        UserInvitation saved = unitOfWork.callInTransaction(() -> {
            invitationRepositoryPort.invalidateAllByEmailAndTenantId(email, command.tenantId());

            UserInvitation invitation = UserInvitation.create(
                    command.tenantId(),
                    email,
                    command.fullName() != null ? command.fullName() : "",
                    command.role(),
                    tokenHash,
                    INVITATION_VALIDITY
            );
            return invitationRepositoryPort.save(invitation);
        });

        String activationLink = invitationBaseUrl + "?token=" + rawToken;
        notificationPort.deliver(NotificationMessage.of(
                email.getValue(),
                "Invitación para unirte a DriveOS Workshop",
                "Hola " + saved.getFullName() + ", has sido invitado a formar parte del taller.\n\n"
                        + "Activa tu cuenta y crea tu contraseña ingresando al siguiente enlace seguro:\n"
                        + activationLink + "\n\n"
                        + "Este enlace es de uso único y tiene una vigencia de 48 horas."
        ));

        return new InviteUserResult(
                saved.getId(),
                saved.getTenantId(),
                saved.getEmail().getValue(),
                saved.getFullName(),
                saved.getRole(),
                saved.getExpiresAt(),
                activationLink
        );
    }

    @Override
    public InvitationDetailsResult getInvitation(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            throw new InvalidTokenException("Token de invitación no proporcionado");
        }

        String tokenHash = tokenSignerPort.hashToken(rawToken.trim());
        UserInvitation invitation = invitationRepositoryPort.findByTokenHash(tokenHash)
                .orElseThrow(() -> new InvalidTokenException("Invitación no encontrada"));

        if (invitation.isExpired()) {
            throw new TokenExpiredException("El enlace de invitación ha expirado");
        }
        if (invitation.isAccepted()) {
            throw new InvalidTokenException("La invitación ya ha sido utilizada previamente");
        }

        return new InvitationDetailsResult(
                invitation.getId(),
                invitation.getTenantId(),
                invitation.getEmail().getValue(),
                invitation.getFullName(),
                invitation.getRole(),
                invitation.isValid(),
                invitation.getExpiresAt()
        );
    }

    @Override
    public AuthResult accept(AcceptInvitationCommand command) {
        if (command.token() == null || command.token().isBlank()) {
            throw new InvalidTokenException("Token de invitación no proporcionado");
        }
        if (command.password() == null || command.password().isBlank()) {
            throw new IllegalArgumentException("La contraseña es requerida");
        }

        String tokenHash = tokenSignerPort.hashToken(command.token().trim());
        UserInvitation invitation = invitationRepositoryPort.findByTokenHash(tokenHash)
                .orElseThrow(() -> new InvalidTokenException("Invitación no encontrada"));

        if (!invitation.isValid()) {
            if (invitation.isExpired()) {
                throw new TokenExpiredException("El enlace de invitación ha expirado");
            }
            throw new InvalidTokenException("La invitación ya ha sido utilizada previamente");
        }

        passwordPolicy.reject(command.password()).ifPresent(motivo -> {
            throw new WeakPasswordException(motivo);
        });

        TenantId tenantId = new TenantId(invitation.getTenantId());
        Email email = invitation.getEmail();

        if (userRepositoryPort.existsByEmailAndTenantId(email, tenantId)) {
            throw new UserAlreadyExistsException(email.getValue());
        }

        Set<Role> roles = roleRepositoryPort.findAllByCodes(Set.of(invitation.getRole()));
        if (roles.isEmpty()) {
            throw new IllegalStateException("El rol asignado no se encuentra en el catalogo");
        }

        PasswordHash passwordHash = PasswordHash.of(passwordEncoderPort.encode(command.password()));
        User user = User.create(tenantId, email, passwordHash, invitation.getFullName(), roles);

        return unitOfWork.callInTransaction(() -> {
            invitation.accept();
            invitationRepositoryPort.save(invitation);

            User savedUser = userRepositoryPort.save(user);

            String accessToken = tokenSignerPort.generateAccessToken(savedUser);
            String rawRefreshToken = tokenSignerPort.generateRefreshToken(savedUser);
            String refreshTokenHash = tokenSignerPort.hashToken(rawRefreshToken);
            Instant refreshTokenExpiry = Instant.now().plus(tokenSignerPort.getRefreshTokenDuration());

            RefreshToken refreshTokenEntity = RefreshToken.create(
                    savedUser.getId(),
                    savedUser.getTenantId().getValue(),
                    refreshTokenHash,
                    refreshTokenExpiry
            );
            refreshTokenRepositoryPort.save(refreshTokenEntity);

            Set<String> roleCodes = savedUser.getRoles().stream()
                    .map(r -> r.getCode().name())
                    .collect(Collectors.toSet());

            return new AuthResult(
                    accessToken,
                    tokenSignerPort.extractTokenId(accessToken),
                    rawRefreshToken,
                    "Bearer",
                    tokenSignerPort.getAccessTokenDuration().toSeconds(),
                    savedUser.getId(),
                    savedUser.getTenantId().getValue(),
                    savedUser.getEmail().getValue(),
                    savedUser.getFullName(),
                    roleCodes
            );
        });
    }

    private String generateSecureToken() {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
