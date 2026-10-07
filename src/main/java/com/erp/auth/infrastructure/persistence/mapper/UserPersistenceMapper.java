package com.erp.auth.infrastructure.persistence.mapper;

import com.erp.auth.domain.model.Role;
import com.erp.auth.domain.model.User;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.domain.valueobject.PasswordHash;
import com.erp.auth.domain.valueobject.TenantId;
import com.erp.auth.infrastructure.persistence.entity.RoleJpaEntity;
import com.erp.auth.infrastructure.persistence.entity.UserJpaEntity;

import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;

public final class UserPersistenceMapper {

    private UserPersistenceMapper() {}

    public static User toDomain(UserJpaEntity entity) {
        if (entity == null) return null;

        Set<Role> domainRoles = entity.getRoles() != null
                ? entity.getRoles().stream().map(RolePersistenceMapper::toDomain).collect(Collectors.toSet())
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

    public static UserJpaEntity toEntity(User domain) {
        if (domain == null) return null;

        Set<RoleJpaEntity> entityRoles = domain.getRoles() != null
                ? domain.getRoles().stream().map(RolePersistenceMapper::toEntity).collect(Collectors.toSet())
                : Collections.emptySet();

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
                entityRoles
        );
    }
}
