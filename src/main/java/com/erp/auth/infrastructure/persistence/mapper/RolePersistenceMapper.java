package com.erp.auth.infrastructure.persistence.mapper;

import com.erp.auth.domain.model.Role;
import com.erp.auth.domain.model.RoleCode;
import com.erp.auth.infrastructure.persistence.entity.RoleJpaEntity;

public final class RolePersistenceMapper {

    private RolePersistenceMapper() {}

    public static Role toDomain(RoleJpaEntity entity) {
        if (entity == null) return null;
        return new Role(
                entity.getId(),
                RoleCode.fromString(entity.getCode()),
                entity.getDescription()
        );
    }

    public static RoleJpaEntity toEntity(Role domain) {
        if (domain == null) return null;
        return new RoleJpaEntity(
                domain.getId(),
                domain.getCode().name(),
                domain.getDescription()
        );
    }
}
