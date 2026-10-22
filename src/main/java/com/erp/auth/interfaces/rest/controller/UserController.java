package com.erp.auth.interfaces.rest.controller;

import com.erp.auth.application.dto.command.RegisterUserCommand;
import com.erp.auth.application.dto.result.UserResult;
import com.erp.auth.application.usecase.ConfirmSecondFactorEnrollmentUseCase;
import com.erp.auth.application.usecase.EnrollSecondFactorUseCase;
import com.erp.auth.application.usecase.GetUserProfileUseCase;
import com.erp.auth.application.usecase.ListTenantUsersUseCase;
import com.erp.auth.application.usecase.RegisterUserUseCase;
import com.erp.auth.domain.exception.TenantContextMissingException;
import com.erp.auth.domain.model.RoleCode;
import com.erp.auth.domain.valueobject.TenantId;
import com.erp.auth.infrastructure.persistence.rls.TenantContextHolder;
import com.erp.auth.interfaces.rest.dto.request.RegisterUserRequest;
import com.erp.auth.interfaces.rest.dto.request.SecondFactorRequest;
import com.erp.auth.interfaces.rest.dto.response.MessageResponse;
import com.erp.auth.interfaces.rest.dto.response.UserResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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

    public UserController(
            RegisterUserUseCase registerUserUseCase,
            GetUserProfileUseCase getUserProfileUseCase,
            ListTenantUsersUseCase listTenantUsersUseCase,
            EnrollSecondFactorUseCase enrollSecondFactorUseCase,
            ConfirmSecondFactorEnrollmentUseCase confirmSecondFactorEnrollmentUseCase) {
        this.registerUserUseCase = registerUserUseCase;
        this.getUserProfileUseCase = getUserProfileUseCase;
        this.listTenantUsersUseCase = listTenantUsersUseCase;
        this.enrollSecondFactorUseCase = enrollSecondFactorUseCase;
        this.confirmSecondFactorEnrollmentUseCase = confirmSecondFactorEnrollmentUseCase;
    }

    @PostMapping("/me/second-factor")
    @PreAuthorize("hasAnyRole('SUPERADMIN', 'ADMIN_TALLER', 'ASESOR', 'MECANICO')")
    @Operation(summary = "Enrolar el segundo factor de autenticacion",
            description = "Genera el secreto y los codigos de recuperacion, y los entrega por el canal de "
                    + "notificacion. La respuesta NO contiene el secreto ni los codigos: son credenciales.")
    public ResponseEntity<MessageResponse> enrollSecondFactor(Authentication authentication) {
        UUID userId = usuarioAutenticado(authentication);
        TenantId tenantId = tenantIdFromContext();

        enrollSecondFactorUseCase.enroll(userId, tenantId.getValue());

        return ResponseEntity.ok(MessageResponse.of(
                "Se ha enviado el secreto y los codigos de recuperacion por el canal de notificacion"));
    }

    @PostMapping("/me/second-factor/confirm")
    @PreAuthorize("hasAnyRole('SUPERADMIN', 'ADMIN_TALLER', 'ASESOR', 'MECANICO')")
    @Operation(summary = "Confirmar el enrolamiento del segundo factor",
            description = "Habilita el segundo factor cuando el codigo es valido")
    public ResponseEntity<MessageResponse> confirmSecondFactor(@Valid @RequestBody SecondFactorRequest request,
                                                              Authentication authentication) {
        UUID userId = usuarioAutenticado(authentication);
        TenantId tenantId = tenantIdFromContext();

        confirmSecondFactorEnrollmentUseCase.confirm(userId, tenantId.getValue(), request.code());

        return ResponseEntity.ok(MessageResponse.of("Segundo factor de autenticacion habilitado"));
    }

    @PostMapping
    @PreAuthorize("hasAnyRole('SUPERADMIN', 'ADMIN_TALLER')")
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

    @GetMapping("/me")
    @PreAuthorize("hasAnyRole('SUPERADMIN', 'ADMIN_TALLER', 'ASESOR', 'MECANICO')")
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
    @PreAuthorize("hasAnyRole('SUPERADMIN', 'ADMIN_TALLER')")
    @Operation(summary = "Listar usuarios del taller", description = "Retorna los usuarios del taller del principal autenticado")
    public ResponseEntity<List<UserResponse>> listUsersByTenant() {
        TenantId tenantId = tenantIdFromContext();

        List<UserResponse> users = listTenantUsersUseCase.listByTenant(tenantId).stream()
                .map(u -> new UserResponse(
                        u.getId(),
                        u.getTenantId().getValue(),
                        u.getEmail().getValue(),
                        u.getFullName(),
                        u.isMfaEnabled(),
                        u.getRoles().stream().map(r -> r.getCode().name()).collect(Collectors.toSet()),
                        u.getCreatedAt()
                ))
                .collect(Collectors.toList());

        return ResponseEntity.ok(users);
    }

    /**
     * Identificador del principal autenticado.
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
     * El rol del principal se toma de las autoridades que el filtro de
     * autenticacion deposita en el contexto de seguridad.
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
