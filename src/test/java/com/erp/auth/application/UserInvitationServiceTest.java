package com.erp.auth.application;

import com.erp.auth.application.dto.command.AcceptInvitationCommand;
import com.erp.auth.application.dto.command.InviteUserCommand;
import com.erp.auth.application.dto.result.AuthResult;
import com.erp.auth.application.dto.result.InvitationDetailsResult;
import com.erp.auth.application.dto.result.InviteUserResult;
import com.erp.auth.application.service.UserInvitationService;
import com.erp.auth.domain.exception.InvalidTokenException;
import com.erp.auth.domain.exception.RoleNotAssignableException;
import com.erp.auth.domain.exception.TokenExpiredException;
import com.erp.auth.domain.exception.UserAlreadyExistsException;
import com.erp.auth.domain.exception.WeakPasswordException;
import com.erp.auth.domain.model.PasswordPolicy;
import com.erp.auth.domain.model.Role;
import com.erp.auth.domain.model.RoleCode;
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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class UserInvitationServiceTest {

    private UserInvitationRepositoryPort invitationRepositoryPort;
    private UserRepositoryPort userRepositoryPort;
    private RoleRepositoryPort roleRepositoryPort;
    private PasswordEncoderPort passwordEncoderPort;
    private TokenSignerPort tokenSignerPort;
    private RefreshTokenRepositoryPort refreshTokenRepositoryPort;
    private NotificationPort notificationPort;
    private PasswordPolicy passwordPolicy;
    private UnitOfWork unitOfWork;

    private UserInvitationService service;

    @BeforeEach
    void setUp() {
        invitationRepositoryPort = mock(UserInvitationRepositoryPort.class);
        userRepositoryPort = mock(UserRepositoryPort.class);
        roleRepositoryPort = mock(RoleRepositoryPort.class);
        passwordEncoderPort = mock(PasswordEncoderPort.class);
        tokenSignerPort = mock(TokenSignerPort.class);
        refreshTokenRepositoryPort = mock(RefreshTokenRepositoryPort.class);
        notificationPort = mock(NotificationPort.class);
        passwordPolicy = new PasswordPolicy(12);
        unitOfWork = new UnitOfWork() {
            @Override
            public void runInTransaction(Runnable runnable) {
                runnable.run();
            }

            @Override
            public <T> T callInTransaction(Supplier<T> supplier) {
                return supplier.get();
            }
        };

        when(tokenSignerPort.hashToken(any())).thenAnswer(inv -> "hashed_" + inv.getArgument(0));

        service = new UserInvitationService(
                invitationRepositoryPort,
                userRepositoryPort,
                roleRepositoryPort,
                passwordEncoderPort,
                tokenSignerPort,
                refreshTokenRepositoryPort,
                notificationPort,
                passwordPolicy,
                unitOfWork,
                "https://app.driveos.pe/activar-cuenta"
        );
    }

    @Test
    @DisplayName("Should invite technician successfully and dispatch notification email")
    void shouldInviteTechnicianSuccessfully() {
        UUID tenantId = UUID.randomUUID();
        when(userRepositoryPort.existsByEmailAndTenantId(any(), any())).thenReturn(false);
        when(invitationRepositoryPort.save(any())).thenAnswer(inv -> inv.getArgument(0));

        InviteUserCommand command = new InviteUserCommand(
                tenantId,
                "mechanic@workshop.pe",
                "Carlos Ramos",
                RoleCode.TECHNICIAN,
                RoleCode.WORKSHOP_ADMIN
        );

        InviteUserResult result = service.invite(command);

        assertThat(result).isNotNull();
        assertThat(result.email()).isEqualTo("mechanic@workshop.pe");
        assertThat(result.role()).isEqualTo(RoleCode.TECHNICIAN);
        assertThat(result.tenantId()).isEqualTo(tenantId);
        assertThat(result.invitationUrl()).contains("token=");

        verify(notificationPort).deliver(any());
        verify(invitationRepositoryPort).invalidateAllByEmailAndTenantId(eq(Email.of("mechanic@workshop.pe")), eq(tenantId));
    }

    @Test
    @DisplayName("Should reject invitation when actor has insufficient role permissions")
    void shouldRejectWhenRoleNotAssignable() {
        InviteUserCommand command = new InviteUserCommand(
                UUID.randomUUID(),
                "admin@workshop.pe",
                "Nuevo Admin",
                RoleCode.WORKSHOP_ADMIN,
                RoleCode.SERVICE_ADVISOR // Service advisor cannot grant WORKSHOP_ADMIN
        );

        assertThatThrownBy(() -> service.invite(command))
                .isInstanceOf(RoleNotAssignableException.class);
    }

    @Test
    @DisplayName("Should reject invitation when user already exists in tenant")
    void shouldRejectWhenUserAlreadyExists() {
        UUID tenantId = UUID.randomUUID();
        when(userRepositoryPort.existsByEmailAndTenantId(any(), any())).thenReturn(true);

        InviteUserCommand command = new InviteUserCommand(
                tenantId,
                "existing@workshop.pe",
                "Existing User",
                RoleCode.TECHNICIAN,
                RoleCode.WORKSHOP_ADMIN
        );

        assertThatThrownBy(() -> service.invite(command))
                .isInstanceOf(UserAlreadyExistsException.class);
    }

    @Test
    @DisplayName("Should get invitation details from valid raw token")
    void shouldGetInvitationDetails() {
        String rawToken = "sampleRawToken123";
        String tokenHash = "hashed_" + rawToken;
        UserInvitation invitation = UserInvitation.create(
                UUID.randomUUID(),
                Email.of("user@workshop.pe"),
                "User Name",
                RoleCode.TECHNICIAN,
                tokenHash,
                Duration.ofHours(48)
        );

        when(invitationRepositoryPort.findByTokenHash(tokenHash)).thenReturn(Optional.of(invitation));

        InvitationDetailsResult result = service.getInvitation(rawToken);

        assertThat(result.email()).isEqualTo("user@workshop.pe");
        assertThat(result.role()).isEqualTo(RoleCode.TECHNICIAN);
        assertThat(result.valid()).isTrue();
    }

    @Test
    @DisplayName("Should reject getting invitation if token has expired")
    void shouldRejectGetInvitationWhenExpired() {
        String rawToken = "sampleRawToken123";
        String tokenHash = "hashed_" + rawToken;
        UserInvitation expiredInvitation = new UserInvitation(
                UUID.randomUUID(),
                UUID.randomUUID(),
                Email.of("user@workshop.pe"),
                "User Name",
                RoleCode.TECHNICIAN,
                tokenHash,
                Instant.now().minus(Duration.ofMinutes(10)),
                null,
                Instant.now().minus(Duration.ofDays(3))
        );

        when(invitationRepositoryPort.findByTokenHash(tokenHash)).thenReturn(Optional.of(expiredInvitation));

        assertThatThrownBy(() -> service.getInvitation(rawToken))
                .isInstanceOf(TokenExpiredException.class);
    }

    @Test
    @DisplayName("Should accept invitation, create user, and issue active session")
    void shouldAcceptInvitationSuccessfully() {
        String rawToken = "validActivationToken456";
        String tokenHash = "hashed_" + rawToken;
        UUID tenantId = UUID.randomUUID();

        UserInvitation invitation = UserInvitation.create(
                tenantId,
                Email.of("newmechanic@workshop.pe"),
                "Reynaldo Machacca",
                RoleCode.TECHNICIAN,
                tokenHash,
                Duration.ofHours(48)
        );

        when(invitationRepositoryPort.findByTokenHash(tokenHash)).thenReturn(Optional.of(invitation));
        when(userRepositoryPort.existsByEmailAndTenantId(any(), any())).thenReturn(false);
        Role role = Role.create(RoleCode.TECHNICIAN, "Automotive Technician");
        when(roleRepositoryPort.findAllByCodes(Set.of(RoleCode.TECHNICIAN))).thenReturn(Set.of(role));
        when(passwordEncoderPort.encode(any())).thenReturn("encodedPassword123");
        when(userRepositoryPort.save(any())).thenAnswer(inv -> inv.getArgument(0));

        when(tokenSignerPort.generateAccessToken(any())).thenReturn("jwt-access-token-xyz");
        when(tokenSignerPort.extractTokenId("jwt-access-token-xyz")).thenReturn("token-id-123");
        when(tokenSignerPort.generateRefreshToken(any())).thenReturn("raw-refresh-token");
        when(tokenSignerPort.getRefreshTokenDuration()).thenReturn(Duration.ofDays(7));
        when(tokenSignerPort.getAccessTokenDuration()).thenReturn(Duration.ofMinutes(15));

        AcceptInvitationCommand command = new AcceptInvitationCommand(rawToken, "StrongP@ssw0rd123!");

        AuthResult authResult = service.accept(command);

        assertThat(authResult).isNotNull();
        assertThat(authResult.accessToken()).isEqualTo("jwt-access-token-xyz");
        assertThat(authResult.email()).isEqualTo("newmechanic@workshop.pe");
        assertThat(authResult.roles()).contains("TECHNICIAN");

        assertThat(invitation.isAccepted()).isTrue();
        verify(invitationRepositoryPort).save(invitation);
        verify(userRepositoryPort).save(any());
        verify(refreshTokenRepositoryPort).save(any());
    }

    @Test
    @DisplayName("Should reject invitation acceptance when password fails security policy")
    void shouldRejectAcceptanceWithWeakPassword() {
        String rawToken = "validActivationToken456";
        String tokenHash = "hashed_" + rawToken;

        UserInvitation invitation = UserInvitation.create(
                UUID.randomUUID(),
                Email.of("newmechanic@workshop.pe"),
                "Reynaldo Machacca",
                RoleCode.TECHNICIAN,
                tokenHash,
                Duration.ofHours(48)
        );

        when(invitationRepositoryPort.findByTokenHash(tokenHash)).thenReturn(Optional.of(invitation));

        AcceptInvitationCommand command = new AcceptInvitationCommand(rawToken, "short");

        assertThatThrownBy(() -> service.accept(command))
                .isInstanceOf(WeakPasswordException.class);
    }
}
