package com.erp.auth.application.service;

import com.erp.auth.application.dto.command.RegisterUserCommand;
import com.erp.auth.application.dto.result.UserResult;
import com.erp.auth.application.usecase.GetUserProfileUseCase;
import com.erp.auth.application.usecase.RegisterUserUseCase;
import com.erp.auth.domain.exception.RoleNotAssignableException;
import com.erp.auth.domain.exception.UserAlreadyExistsException;
import com.erp.auth.domain.exception.WeakPasswordException;
import com.erp.auth.domain.model.PasswordPolicy;
import com.erp.auth.domain.exception.UserNotFoundException;
import com.erp.auth.domain.model.Role;
import com.erp.auth.domain.model.RoleAssignmentPolicy;
import com.erp.auth.domain.model.RoleCode;
import com.erp.auth.domain.model.User;
import com.erp.auth.domain.port.PasswordEncoderPort;
import com.erp.auth.domain.port.RoleRepositoryPort;
import com.erp.auth.domain.port.UnitOfWork;
import com.erp.auth.domain.port.UserRepositoryPort;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.domain.valueobject.PasswordHash;
import com.erp.auth.domain.valueobject.TenantId;
import java.util.EnumSet;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

public class RegisterUserService implements RegisterUserUseCase, GetUserProfileUseCase {

    private final UserRepositoryPort userRepositoryPort;
    private final RoleRepositoryPort roleRepositoryPort;
    private final PasswordEncoderPort passwordEncoderPort;
    private final PasswordPolicy passwordPolicy;
    private final UnitOfWork unitOfWork;

    public RegisterUserService(UserRepositoryPort userRepositoryPort,
                               RoleRepositoryPort roleRepositoryPort,
                               PasswordEncoderPort passwordEncoderPort,
                               PasswordPolicy passwordPolicy,
                               UnitOfWork unitOfWork) {
        this.userRepositoryPort = userRepositoryPort;
        this.roleRepositoryPort = roleRepositoryPort;
        this.passwordEncoderPort = passwordEncoderPort;
        this.passwordPolicy = passwordPolicy;
        this.unitOfWork = unitOfWork;
    }

    @Override
    public UserResult register(RegisterUserCommand command) {
        if (command.tenantId() == null || command.email() == null || command.password() == null) {
            throw new IllegalArgumentException("Taller, correo y contraseña son obligatorios");
        }

        // La politica se comprueba ANTES de tocar la base de datos: una
        // contrasena corta o demasiado usada no merece una escritura.
        passwordPolicy.reject(command.password()).ifPresent(motivo -> {
            throw new WeakPasswordException(motivo);
        });

        TenantId tenantId = command.tenantId();
        Email email = Email.of(command.email());
        if (userRepositoryPort.existsByEmailAndTenantId(email, tenantId)) {
            throw new UserAlreadyExistsException(email.getValue());
        }

        Set<RoleCode> roleCodes = resolveAssignableRoles(command);
        Set<Role> roles = roleRepositoryPort.findAllByCodes(roleCodes);
        if (roles.size() != roleCodes.size()) {
            throw new IllegalArgumentException("Alguno de los roles solicitados no existe en el catalogo");
        }

        PasswordHash passwordHash = PasswordHash.of(passwordEncoderPort.encode(command.password()));
        User user = User.create(tenantId, email, passwordHash, command.fullName(), roles);

        // El alta confirma la escritura del usuario dentro de un limite
        // transaccional explicito, como el resto de las escrituras del
        // servicio: los adaptadores de persistencia se unen a la transaccion
        // en curso y no abren una propia.
        User savedUser = unitOfWork.callInTransaction(() -> userRepositoryPort.save(user));

        return toUserResult(savedUser);
    }

    /**
     * Los roles que se conceden son los que el actor tiene permitidos. Un rol
     * solicitado fuera de ese conjunto se rechaza: nadie concede un
     * privilegio superior al suyo.
     */
    private Set<RoleCode> resolveAssignableRoles(RegisterUserCommand command) {
        Set<RoleCode> permitted = RoleAssignmentPolicy.assignableRolesFor(command.actorRole());
        if (permitted.isEmpty()) {
            throw new RoleNotAssignableException(command.actorRole());
        }

        Set<RoleCode> requested = (command.requestedRoles() == null || command.requestedRoles().isEmpty())
                ? EnumSet.of(RoleAssignmentPolicy.defaultRoleFor(command.actorRole()))
                : EnumSet.copyOf(command.requestedRoles());

        for (RoleCode role : requested) {
            if (!permitted.contains(role)) {
                throw new RoleNotAssignableException(command.actorRole(), role);
            }
        }
        return requested;
    }

    @Override
    public UserResult getProfile(UUID userId, TenantId tenantId) {
        User user = userRepositoryPort.findByIdAndTenantId(userId, tenantId)
                .orElseThrow(() -> new UserNotFoundException(userId.toString()));
        return toUserResult(user);
    }

    private UserResult toUserResult(User user) {
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
}
