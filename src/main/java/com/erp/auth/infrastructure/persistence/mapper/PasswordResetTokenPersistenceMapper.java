package com.erp.auth.infrastructure.persistence.mapper;

import com.erp.auth.domain.model.PasswordResetToken;
import com.erp.auth.infrastructure.persistence.entity.PasswordResetTokenJpaEntity;

public final class PasswordResetTokenPersistenceMapper {

    private PasswordResetTokenPersistenceMapper() {}

    public static PasswordResetToken toDomain(PasswordResetTokenJpaEntity entity) {
        if (entity == null) return null;
        return new PasswordResetToken(
                entity.getId(),
                entity.getUserId(),
                entity.getTokenHash(),
                entity.getExpiresAt(),
                entity.getUsedAt(),
                entity.getCreatedAt()
        );
    }

    public static PasswordResetTokenJpaEntity toEntity(PasswordResetToken domain) {
        if (domain == null) return null;
        return new PasswordResetTokenJpaEntity(
                domain.getId(),
                domain.getUserId(),
                domain.getTokenHash(),
                domain.getExpiresAt(),
                domain.getUsedAt(),
                domain.getCreatedAt()
        );
    }
}
