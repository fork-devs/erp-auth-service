package com.erp.auth.application.service;

import com.erp.auth.application.dto.command.RegisterUserCommand;
import com.erp.auth.application.dto.result.UserResult;
import com.erp.auth.application.usecase.GetUserProfileUseCase;
import com.erp.auth.application.usecase.RegisterUserUseCase;
import com.erp.auth.domain.exception.UserAlreadyExistsException;
import com.erp.auth.domain.exception.UserNotFoundException;
import com.erp.auth.domain.model.Role;
import com.erp.auth.domain.model.RoleCode;
import com.erp.auth.domain.model.User;
import com.erp.auth.domain.port.PasswordEncoderPort;
import com.erp.auth.domain.port.RoleRepositoryPort;
import com.erp.auth.domain.port.UserRepositoryPort;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.domain.valueobject.PasswordHash;
import com.erp.auth.domain.valueobject.TenantId;

import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

public class RegisterUserService implements RegisterUserUseCase, GetUserProfileUseCase {

    private final UserRepositoryPort userRepositoryPort;
    private final RoleRepositoryPort roleRepositoryPort;
    private final PasswordEncoderPort passwordEncoderPort;

    public RegisterUserService(
            UserRepositoryPort userRepositoryPort,
            RoleRepositoryPort roleRepositoryPort,
            PasswordEncoderPort passwordEncoderPort) {
        this.userRepositoryPort = userRepositoryPort;
        this.roleRepositoryPort = roleRepositoryPort;
        this.passwordEncoderPort = passwordEncoderPort;
    }

    @Override
    public UserResult register(RegisterUserCommand command) {
        if (command.tenantId() == null || command.email() == null || command.password() == null) {
            throw new IllegalArgumentException("TenantId, email y contraseña son obligatorios");
        }

        Email email = Email.of(command.email());
        if (userRepositoryPort.existsByEmail(email)) {
            throw new UserAlreadyExistsException(email.getValue());
        }

        TenantId tenantId = new TenantId(command.tenantId());
        PasswordHash passwordHash = PasswordHash.of(passwordEncoderPort.encode(command.password()));

        Set<RoleCode> roleCodes = (command.roleCodes() == null || command.roleCodes().isEmpty())
                ? Set.of(RoleCode.ASESOR)
                : command.roleCodes().stream().map(RoleCode::fromString).collect(Collectors.toSet());

        Set<Role> roles = roleRepositoryPort.findAllByCodes(roleCodes);
        if (roles.isEmpty()) {
            // Si no se encontraron por código, buscar rol por defecto ASESOR
            roleRepositoryPort.findByCode(RoleCode.ASESOR).ifPresent(roles::add);
        }

        User user = User.create(tenantId, email, passwordHash, command.fullName(), roles);
        User savedUser = userRepositoryPort.save(user);

        return toUserResult(savedUser);
    }

    @Override
    public UserResult getProfile(UUID userId) {
        User user = userRepositoryPort.findById(userId)
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
