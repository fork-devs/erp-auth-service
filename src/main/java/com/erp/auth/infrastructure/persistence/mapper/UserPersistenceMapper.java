package com.erp.auth.infrastructure.persistence.mapper;

import com.erp.auth.domain.model.Role;
import com.erp.auth.domain.model.User;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.domain.valueobject.PasswordHash;
import com.erp.auth.domain.valueobject.TenantId;
import com.erp.auth.infrastructure.persistence.entity.RoleJpaEntity;
import com.erp.auth.infrastructure.persistence.entity.UserJpaEntity;
import com.erp.auth.infrastructure.persistence.entity.UserRoleId;
import com.erp.auth.infrastructure.persistence.entity.UserRoleJpaEntity;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

public final class UserPersistenceMapper {

    private UserPersistenceMapper() {}

    public static User toDomain(UserJpaEntity entity) {
        if (entity == null) return null;

        Set<Role> domainRoles = entity.getUserRoles() != null
                ? entity.getUserRoles().stream()
                    .map(UserRoleJpaEntity::getRole)
                    .filter(role -> role != null)
                    .map(RolePersistenceMapper::toDomain)
                    .collect(Collectors.toSet())
                : Collections.emptySet();

        return new User(
                entity.getId(),
                new TenantId(entity.getTenantId()),
                Email.of(entity.getEmail()),
                PasswordHash.of(entity.getPasswordHash()),
                entity.getFullName(),
                Boolean.TRUE.equals(entity.getMfaEnabled()),
                entity.getFailedAttempts() != null ? entity.getFailedAttempts() : 0,
                entity.getLockedUntil(),
                domainRoles,
                entity.getCreatedAt()
        );
    }

    /**
     * Los roles del dominio se traducen a asignaciones de rol. El tenant de la
     * asignacion es el del usuario: la columna tenant_id de user_roles es una
     * copia del tenant del usuario y no un dato independiente.
     *
     * @param managedRoles los roles ya gestionados por la sesion, indexados por
     *                     identificador. Se exigen gestionados porque la
     *                     referencia debe apuntar a la fila real del catalogo.
     */
    public static UserJpaEntity toEntity(User domain, Set<RoleJpaEntity> managedRoles) {
        if (domain == null) return null;

        Set<UserRoleJpaEntity> entityUserRoles = new HashSet<>();
        if (domain.getRoles() != null) {
            for (Role role : domain.getRoles()) {
                RoleJpaEntity managed = findManagedRole(managedRoles, role.getId());
                entityUserRoles.add(new UserRoleJpaEntity(
                        new UserRoleId(domain.getId(), managed.getId(), domain.getTenantId().getValue()),
                        managed));
            }
        }

        return new UserJpaEntity(
                domain.getId(),
                domain.getTenantId().getValue(),
                domain.getEmail().getValue(),
                domain.getPasswordHash().getValue(),
                domain.getFullName(),
                domain.isMfaEnabled(),
                domain.getFailedAttempts(),
                domain.getLockedUntil(),
                domain.getCreatedAt(),
                entityUserRoles
        );
    }

    private static RoleJpaEntity findManagedRole(Set<RoleJpaEntity> managedRoles, UUID roleId) {
        if (managedRoles != null) {
            for (RoleJpaEntity managed : managedRoles) {
                if (managed.getId().equals(roleId)) {
                    return managed;
                }
            }
        }
        throw new IllegalStateException("El rol " + roleId + " no esta gestionado por la sesion de persistencia");
    }
}
