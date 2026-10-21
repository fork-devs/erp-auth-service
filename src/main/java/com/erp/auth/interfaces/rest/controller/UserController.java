package com.erp.auth.interfaces.rest.controller;

import com.erp.auth.application.dto.command.RegisterUserCommand;
import com.erp.auth.application.dto.result.UserResult;
import com.erp.auth.application.usecase.GetUserProfileUseCase;
import com.erp.auth.application.usecase.RegisterUserUseCase;
import com.erp.auth.domain.port.UserRepositoryPort;
import com.erp.auth.domain.exception.TenantContextMissingException;
import com.erp.auth.domain.valueobject.TenantId;
import com.erp.auth.infrastructure.persistence.rls.TenantContextHolder;
import com.erp.auth.interfaces.rest.dto.request.RegisterUserRequest;
import com.erp.auth.interfaces.rest.dto.response.UserResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/v1/users")
@Tag(name = "Users", description = "Endpoints para administración de usuarios y perfil")
@SecurityRequirement(name = "bearerAuth")
public class UserController {

    private final RegisterUserUseCase registerUserUseCase;
    private final GetUserProfileUseCase getUserProfileUseCase;
    private final UserRepositoryPort userRepositoryPort;

    public UserController(
            RegisterUserUseCase registerUserUseCase,
            GetUserProfileUseCase getUserProfileUseCase,
            UserRepositoryPort userRepositoryPort) {
        this.registerUserUseCase = registerUserUseCase;
        this.getUserProfileUseCase = getUserProfileUseCase;
        this.userRepositoryPort = userRepositoryPort;
    }

    @PostMapping
    @Operation(summary = "Registrar nuevo usuario", description = "Crea un usuario para un taller con roles especificados (ASESOR, MECANICO, ADMIN_TALLER)")
    public ResponseEntity<UserResponse> createUser(@Valid @RequestBody RegisterUserRequest request) {
        RegisterUserCommand command = new RegisterUserCommand(
                request.tenantId(),
                request.email(),
                request.password(),
                request.fullName(),
                request.roles()
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
    @Operation(summary = "Perfil del usuario autenticado", description = "Retorna los datos del usuario correspondiente al token JWT actual")
    public ResponseEntity<UserResponse> getCurrentUser(Authentication authentication) {
        UUID userId = UUID.fromString(authentication.getName());
        UUID tenantId = TenantContextHolder.getTenantId();
        if (tenantId == null) {
            throw new TenantContextMissingException(
                    "La consulta del perfil requiere un contexto de taller establecido");
        }
        UserResult result = getUserProfileUseCase.getProfile(userId, new TenantId(tenantId));

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
    @Operation(summary = "Listar usuarios del taller", description = "Retorna los usuarios del tenant actual respetando aislamiento RLS")
    public ResponseEntity<List<UserResponse>> listUsersByTenant() {
        UUID tenantId = TenantContextHolder.getTenantId();
        if (tenantId == null) {
            return ResponseEntity.ok(List.of());
        }

        List<UserResponse> users = userRepositoryPort.findAllByTenantId(new TenantId(tenantId)).stream()
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
}
