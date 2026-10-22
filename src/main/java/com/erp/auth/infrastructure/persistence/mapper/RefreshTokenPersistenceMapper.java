package com.erp.auth.infrastructure.persistence.mapper;

import com.erp.auth.domain.model.RefreshToken;
import com.erp.auth.infrastructure.persistence.entity.RefreshTokenJpaEntity;

public final class RefreshTokenPersistenceMapper {

    private RefreshTokenPersistenceMapper() {}

    public static RefreshToken toDomain(RefreshTokenJpaEntity entity) {
        if (entity == null) return null;
        return new RefreshToken(
                entity.getId(),
                entity.getUserId(),
                entity.getTenantId(),
                entity.getTokenHash(),
                entity.getExpiresAt(),
                Boolean.TRUE.equals(entity.getRevoked()),
                entity.getCreatedAt()
        );
    }

    public static RefreshTokenJpaEntity toEntity(RefreshToken domain) {
        if (domain == null) return null;
        return new RefreshTokenJpaEntity(
                domain.getId(),
                domain.getUserId(),
                domain.getTenantId(),
                domain.getTokenHash(),
                domain.getExpiresAt(),
                domain.isRevoked(),
                domain.getCreatedAt()
        );
    }
}
