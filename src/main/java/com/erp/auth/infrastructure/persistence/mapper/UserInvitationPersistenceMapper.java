package com.erp.auth.infrastructure.persistence.mapper;

import com.erp.auth.domain.model.RoleCode;
import com.erp.auth.domain.model.UserInvitation;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.infrastructure.persistence.entity.UserInvitationJpaEntity;

public final class UserInvitationPersistenceMapper {

    private UserInvitationPersistenceMapper() {}

    public static UserInvitation toDomain(UserInvitationJpaEntity entity) {
        if (entity == null) return null;
        return new UserInvitation(
                entity.getId(),
                entity.getTenantId(),
                Email.of(entity.getEmail()),
                entity.getFullName(),
                RoleCode.fromString(entity.getRole()),
                entity.getTokenHash(),
                entity.getExpiresAt(),
                entity.getAcceptedAt(),
                entity.getCreatedAt()
        );
    }

    public static UserInvitationJpaEntity toEntity(UserInvitation domain) {
        if (domain == null) return null;
        return new UserInvitationJpaEntity(
                domain.getId(),
                domain.getTenantId(),
                domain.getEmail().getValue(),
                domain.getFullName(),
                domain.getRole().name(),
                domain.getTokenHash(),
                domain.getExpiresAt(),
                domain.getAcceptedAt(),
                domain.getCreatedAt()
        );
    }
}
