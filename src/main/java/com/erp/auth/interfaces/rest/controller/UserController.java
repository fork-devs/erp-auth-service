package com.erp.auth.interfaces.rest.controller;

import com.erp.auth.application.dto.command.RegisterUserCommand;
import com.erp.auth.application.dto.command.UpdateUserEmailCommand;
import com.erp.auth.application.dto.command.UpdateUserPasswordCommand;
import com.erp.auth.application.dto.result.AuthResult;
import com.erp.auth.application.dto.result.UserResult;
import com.erp.auth.application.usecase.ConfirmSecondFactorEnrollmentUseCase;
import com.erp.auth.application.usecase.EnrollSecondFactorUseCase;
import com.erp.auth.application.usecase.GetUserByIdUseCase;
import com.erp.auth.application.usecase.GetUserProfileUseCase;
import com.erp.auth.application.usecase.ListTenantUsersUseCase;
import com.erp.auth.application.usecase.RegisterUserUseCase;
import com.erp.auth.application.usecase.UpdateUserEmailUseCase;
import com.erp.auth.application.usecase.UpdateUserPasswordUseCase;
import com.erp.auth.domain.exception.TenantContextMissingException;
import com.erp.auth.domain.exception.UserNotFoundException;
import com.erp.auth.domain.model.RoleCode;
import com.erp.auth.domain.valueobject.TenantId;
import com.erp.auth.infrastructure.adapter.external.MediaUploadClient;
import com.erp.auth.infrastructure.persistence.entity.UserJpaEntity;
import com.erp.auth.infrastructure.persistence.repository.SpringDataUserRepository;
import com.erp.auth.infrastructure.persistence.rls.TenantContextHolder;
import com.erp.auth.interfaces.rest.dto.request.RegisterUserRequest;
import com.erp.auth.interfaces.rest.dto.request.SecondFactorRequest;
import com.erp.auth.interfaces.rest.dto.request.UpdateEmailRequest;
import com.erp.auth.interfaces.rest.dto.request.UpdatePasswordRequest;
import com.erp.auth.interfaces.rest.dto.response.AuthResponse;
import com.erp.auth.interfaces.rest.dto.response.MessageResponse;
import com.erp.auth.interfaces.rest.dto.response.UserResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/v1/users")
@Tag(name = "Users", description = "Endpoints para administración de usuarios y perfil")
@SecurityRequirement(name = "bearerAuth")
public class UserController {

    private final RegisterUserUseCase registerUserUseCase;
    private final GetUserProfileUseCase getUserProfileUseCase;
    private final ListTenantUsersUseCase listTenantUsersUseCase;
    private final EnrollSecondFactorUseCase enrollSecondFactorUseCase;
    private final ConfirmSecondFactorEnrollmentUseCase confirmSecondFactorEnrollmentUseCase;
    private final GetUserByIdUseCase getUserByIdUseCase;
    private final UpdateUserEmailUseCase updateUserEmailUseCase;
    private final UpdateUserPasswordUseCase updateUserPasswordUseCase;
    private final com.erp.auth.application.usecase.InviteUserUseCase inviteUserUseCase;

    @Autowired(required = false)
    private MediaUploadClient mediaUploadClient;

    @Autowired(required = false)
    private SpringDataUserRepository userRepository;

    public UserController(
            RegisterUserUseCase registerUserUseCase,
            GetUserProfileUseCase getUserProfileUseCase,
            ListTenantUsersUseCase listTenantUsersUseCase,
            EnrollSecondFactorUseCase enrollSecondFactorUseCase,
            ConfirmSecondFactorEnrollmentUseCase confirmSecondFactorEnrollmentUseCase) {
        this(registerUserUseCase, getUserProfileUseCase, listTenantUsersUseCase,
                enrollSecondFactorUseCase, confirmSecondFactorEnrollmentUseCase, null, null, null, null);
    }

    public UserController(
            RegisterUserUseCase registerUserUseCase,
            GetUserProfileUseCase getUserProfileUseCase,
            ListTenantUsersUseCase listTenantUsersUseCase,
            EnrollSecondFactorUseCase enrollSecondFactorUseCase,
            ConfirmSecondFactorEnrollmentUseCase confirmSecondFactorEnrollmentUseCase,
            GetUserByIdUseCase getUserByIdUseCase,
            UpdateUserEmailUseCase updateUserEmailUseCase,
            UpdateUserPasswordUseCase updateUserPasswordUseCase) {
        this(registerUserUseCase, getUserProfileUseCase, listTenantUsersUseCase,
                enrollSecondFactorUseCase, confirmSecondFactorEnrollmentUseCase,
                getUserByIdUseCase, updateUserEmailUseCase, updateUserPasswordUseCase, null);
    }

    @org.springframework.beans.factory.annotation.Autowired
    public UserController(
            RegisterUserUseCase registerUserUseCase,
            GetUserProfileUseCase getUserProfileUseCase,
            ListTenantUsersUseCase listTenantUsersUseCase,
            EnrollSecondFactorUseCase enrollSecondFactorUseCase,
            ConfirmSecondFactorEnrollmentUseCase confirmSecondFactorEnrollmentUseCase,
            GetUserByIdUseCase getUserByIdUseCase,
            UpdateUserEmailUseCase updateUserEmailUseCase,
            UpdateUserPasswordUseCase updateUserPasswordUseCase,
            @org.springframework.beans.factory.annotation.Autowired(required = false) com.erp.auth.application.usecase.InviteUserUseCase inviteUserUseCase) {
        this.registerUserUseCase = registerUserUseCase;
        this.getUserProfileUseCase = getUserProfileUseCase;
        this.listTenantUsersUseCase = listTenantUsersUseCase;
        this.enrollSecondFactorUseCase = enrollSecondFactorUseCase;
        this.confirmSecondFactorEnrollmentUseCase = confirmSecondFactorEnrollmentUseCase;
        this.getUserByIdUseCase = getUserByIdUseCase;
        this.updateUserEmailUseCase = updateUserEmailUseCase;
        this.updateUserPasswordUseCase = updateUserPasswordUseCase;
        this.inviteUserUseCase = inviteUserUseCase;
    }

    @PostMapping("/me/second-factor")
    @PreAuthorize("hasAnyRole('SUPERADMIN', 'WORKSHOP_ADMIN', 'ADMIN_TALLER', 'SERVICE_ADVISOR', 'ASESOR', 'TECHNICIAN', 'MECANICO')")
    @Operation(summary = "Enrolar el segundo factor de autenticacion",
            description = "Genera el secreto y los codigos de recuperacion, y los entrega por el canal de "
                    + "notificacion. La respuesta NO contiene el secreto ni los codigos: son credenciales.")
    public ResponseEntity<MessageResponse> enrollSecondFactor(Authentication authentication) {
        UUID userId = usuarioAutenticado(authentication);
        TenantId tenantId = tenantIdFromContext();

        enrollSecondFactorUseCase.enroll(userId, tenantId.value());

        return ResponseEntity.ok(MessageResponse.of(
                "Se ha enviado el secreto y los codigos de recuperacion por el canal de notificacion"));
    }

    @PostMapping("/me/second-factor/confirm")
    @PreAuthorize("hasAnyRole('SUPERADMIN', 'WORKSHOP_ADMIN', 'ADMIN_TALLER', 'SERVICE_ADVISOR', 'ASESOR', 'TECHNICIAN', 'MECANICO')")
    @Operation(summary = "Confirmar el enrolamiento del segundo factor",
            description = "Habilita el segundo factor cuando el codigo es valido")
    public ResponseEntity<MessageResponse> confirmSecondFactor(@Valid @RequestBody SecondFactorRequest request,
                                                              Authentication authentication) {
        UUID userId = usuarioAutenticado(authentication);
        TenantId tenantId = tenantIdFromContext();

        confirmSecondFactorEnrollmentUseCase.confirm(userId, tenantId.value(), request.code());

        return ResponseEntity.ok(MessageResponse.of("Segundo factor de autenticacion habilitado"));
    }

    @PostMapping
    @PreAuthorize("hasAnyRole('SUPERADMIN', 'WORKSHOP_ADMIN', 'ADMIN_TALLER')")
    @Operation(summary = "Registrar nuevo usuario",
            description = "Crea un usuario dentro del taller del principal autenticado. "
                    + "El rol solicitado solo se asigna si el rol del principal tiene permiso para concederlo.")
    public ResponseEntity<UserResponse> createUser(@Valid @RequestBody RegisterUserRequest request,
                                                   Authentication authentication) {
        TenantId tenantId = tenantIdFromContext();
        RoleCode actorRole = actorRoleFrom(authentication);

        Set<RoleCode> requestedRoles = request.role() == null
                ? EnumSet.noneOf(RoleCode.class)
                : EnumSet.of(request.role());

        RegisterUserCommand command = new RegisterUserCommand(
                tenantId,
                request.email(),
                request.password(),
                request.fullName(),
                requestedRoles,
                actorRole
        );
        UserResult result = registerUserUseCase.register(command);

        return ResponseEntity.status(HttpStatus.CREATED).body(new UserResponse(
                result.id(),
                result.tenantId(),
                result.email(),
                result.fullName(),
                result.mfaEnabled(),
                result.roles(),
                result.createdAt()
        ));
    }

    @PostMapping("/invitations")
    @PreAuthorize("hasAnyRole('SUPERADMIN', 'WORKSHOP_ADMIN', 'ADMIN_TALLER')")
    @Operation(summary = "Invitar nuevo colaborador por correo",
            description = "Emite una invitación segura para que el colaborador active su cuenta mediante enlace")
    public ResponseEntity<com.erp.auth.interfaces.rest.dto.response.InviteUserResponse> inviteUser(
            @Valid @RequestBody com.erp.auth.interfaces.rest.dto.request.InviteUserRequest request,
            Authentication authentication) {
        if (inviteUserUseCase == null) {
            throw new IllegalStateException("InviteUserUseCase is not configured");
        }
        TenantId tenantId = tenantIdFromContext();
        RoleCode actorRole = actorRoleFrom(authentication);

        com.erp.auth.application.dto.command.InviteUserCommand command =
                new com.erp.auth.application.dto.command.InviteUserCommand(
                        tenantId.value(),
                        request.email(),
                        request.fullName(),
                        request.role(),
                        actorRole
                );
        com.erp.auth.application.dto.result.InviteUserResult result = inviteUserUseCase.invite(command);

        return ResponseEntity.status(HttpStatus.CREATED).body(
                new com.erp.auth.interfaces.rest.dto.response.InviteUserResponse(
                        result.id(),
                        result.tenantId(),
                        result.email(),
                        result.fullName(),
                        result.role(),
                        result.expiresAt(),
                        result.invitationUrl()
                )
        );
    }

    @GetMapping("/me")
    @PreAuthorize("hasAnyRole('SUPERADMIN', 'WORKSHOP_ADMIN', 'ADMIN_TALLER', 'SERVICE_ADVISOR', 'ASESOR', 'TECHNICIAN', 'MECANICO')")
    @Operation(summary = "Perfil del usuario autenticado", description = "Retorna los datos del usuario correspondiente al token JWT actual")
    public ResponseEntity<UserResponse> getCurrentUser(Authentication authentication) {
        UUID userId = UUID.fromString(authentication.getName());
        UserResult result = getUserProfileUseCase.getProfile(userId, tenantIdFromContext());

        return ResponseEntity.ok(new UserResponse(
                result.id(),
                result.tenantId(),
                result.email(),
                result.fullName(),
                result.mfaEnabled(),
                result.roles(),
                result.createdAt()
        ));
    }

    @GetMapping
    @PreAuthorize("hasAnyRole('SUPERADMIN', 'WORKSHOP_ADMIN', 'ADMIN_TALLER')")
    @Operation(summary = "Listar usuarios del taller", description = "Retorna los usuarios del taller del principal autenticado")
    public ResponseEntity<List<UserResponse>> listUsersByTenant() {
        TenantId tenantId = tenantIdFromContext();

        List<UserResponse> users = listTenantUsersUseCase.listByTenant(tenantId).stream()
                .map(u -> new UserResponse(
                        u.getId(),
                        u.getTenantId().value(),
                        u.getEmail().value(),
                        u.getFullName(),
                        u.isMfaEnabled(),
                        u.getRoles().stream().map(r -> r.getCode().name()).collect(Collectors.toSet()),
                        u.getCreatedAt()
                ))
                .collect(Collectors.toList());

        return ResponseEntity.ok(users);
    }

    @GetMapping("/{userId}")
    @PreAuthorize("isAuthenticated() and @userSecurityService.isCurrentUser(#userId)")
    @Operation(summary = "Obtener usuario por ID", description = "Retorna los datos del usuario especificado si es el propio usuario o ADMIN")
    public ResponseEntity<UserResponse> getUserById(@PathVariable("userId") UUID userId) {
        UserResult result = getUserByIdUseCase.getUserById(userId);
        return ResponseEntity.ok(new UserResponse(
                result.id(),
                result.tenantId(),
                result.email(),
                result.fullName(),
                result.mfaEnabled(),
                result.roles(),
                result.createdAt()
        ));
    }

    @PutMapping("/{userId}/email")
    @PreAuthorize("isAuthenticated() and @userSecurityService.isCurrentUser(#userId)")
    @Operation(summary = "Actualizar email de usuario", description = "Actualiza el correo y reemite nuevo par de tokens")
    public ResponseEntity<AuthResponse> updateEmail(
            @PathVariable("userId") UUID userId,
            @Valid @RequestBody UpdateEmailRequest request) {
        AuthResult result = updateUserEmailUseCase.updateEmail(
                new UpdateUserEmailCommand(userId, request.email()));
        return ResponseEntity.ok(new AuthResponse(
                result.accessToken(),
                result.accessTokenId(),
                result.refreshToken(),
                result.tokenType(),
                result.expiresInSeconds(),
                result.userId(),
                result.tenantId(),
                result.email(),
                result.fullName(),
                result.roles()
        ));
    }

    @PutMapping(value = "/{userId}/avatar", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @PreAuthorize("isAuthenticated() and @userSecurityService.isCurrentUser(#userId)")
    @Transactional
    @Operation(summary = "Subir avatar de usuario", description = "Sube una foto de perfil a Cloudflare R2 y actualiza el avatar del usuario")
    public ResponseEntity<UserResponse> uploadAvatar(
            @PathVariable("userId") UUID userId,
            @RequestParam("file") MultipartFile file) {
        if (mediaUploadClient == null || userRepository == null) {
            throw new IllegalStateException("Media upload dependencies are not configured");
        }
        UserJpaEntity entity = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found: " + userId));
        MediaUploadClient.UploadedMedia uploaded = mediaUploadClient.upload(file, "avatars/" + userId);
        entity.setAvatarUrl(uploaded.url());
        userRepository.save(entity);
        UserResult result = getUserByIdUseCase.getUserById(userId);
        return ResponseEntity.ok(new UserResponse(
                result.id(),
                result.tenantId(),
                result.email(),
                result.fullName(),
                result.mfaEnabled(),
                result.roles(),
                result.createdAt(),
                entity.getAvatarUrl()
        ));
    }

    @PutMapping("/{userId}/password")
    @PreAuthorize("isAuthenticated() and @userSecurityService.isCurrentUser(#userId)")
    @Operation(summary = "Actualizar contraseña de usuario", description = "Cambia la clave verificando la actual y revoca sesiones en todos los dispositivos")
    public ResponseEntity<MessageResponse> updatePassword(
            @PathVariable("userId") UUID userId,
            @Valid @RequestBody UpdatePasswordRequest request) {
        updateUserPasswordUseCase.updatePassword(
                new UpdateUserPasswordCommand(userId, request.currentPassword(), request.newPassword()));
        return ResponseEntity.ok(MessageResponse.of("Password updated successfully"));
    }

    /**
     * Resolves the authenticated user identifier from the security context.
     *
     * @param authentication the current authentication token
     * @return authenticated user UUID
     */
    private UUID usuarioAutenticado(Authentication authentication) {
        return UUID.fromString(authentication.getName());
    }

    private TenantId tenantIdFromContext() {
        UUID tenantId = TenantContextHolder.getTenantId();
        if (tenantId == null) {
            throw new TenantContextMissingException(
                    "La operacion requiere un contexto de taller establecido y no lo tiene.");
        }
        return new TenantId(tenantId);
    }

    /**
     * Resolves the primary role of the principal from the granted authorities in the security context.
     *
     * @param authentication the current authentication token
     * @return the resolved RoleCode, or null if unassigned
     */
    private RoleCode actorRoleFrom(Authentication authentication) {
        if (authentication == null || authentication.getAuthorities() == null) {
            return null;
        }
        return authentication.getAuthorities().stream()
                .map(authority -> authority.getAuthority())
                .filter(authority -> authority != null && authority.startsWith("ROLE_"))
                .map(authority -> authority.substring("ROLE_".length()))
                .map(RoleCode::fromString)
                .findFirst()
                .orElse(null);
    }
}
