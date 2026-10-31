package com.erp.auth.infrastructure.persistence.mapper;

import com.erp.auth.domain.model.OtpVerification;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.infrastructure.persistence.entity.OtpVerificationJpaEntity;

public final class OtpVerificationPersistenceMapper {

    private OtpVerificationPersistenceMapper() {
    }

    public static OtpVerificationJpaEntity toEntity(OtpVerification domain) {
        if (domain == null) {
            return null;
        }
        return new OtpVerificationJpaEntity(
                domain.getId(),
                domain.getEmail().getValue(),
                domain.getCodeHash(),
                domain.getAttempts(),
                domain.isVerified(),
                domain.getExpiresAt(),
                domain.getCreatedAt()
        );
    }

    public static OtpVerification toDomain(OtpVerificationJpaEntity entity) {
        if (entity == null) {
            return null;
        }
        return new OtpVerification(
                entity.getId(),
                new Email(entity.getEmail()),
                entity.getCodeHash(),
                entity.getAttempts(),
                entity.isVerified(),
                entity.getExpiresAt(),
                entity.getCreatedAt()
        );
    }
}
