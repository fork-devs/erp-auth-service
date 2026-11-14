package com.erp.auth.infrastructure.persistence.mapper;

import com.erp.auth.domain.model.OtpPurpose;
import com.erp.auth.domain.model.OtpVerification;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.domain.valueobject.OtpCodeHash;
import com.erp.auth.domain.valueobject.OtpVerificationId;
import com.erp.auth.domain.valueobject.TenantId;
import com.erp.auth.domain.valueobject.UserId;
import com.erp.auth.infrastructure.persistence.entity.OtpVerificationJpaEntity;

public final class OtpVerificationPersistenceMapper {

    private OtpVerificationPersistenceMapper() {
    }

    public static OtpVerificationJpaEntity toEntity(OtpVerification domain) {
        if (domain == null) {
            return null;
        }
        return new OtpVerificationJpaEntity(
                domain.getId().value(),
                domain.getTenantId() != null ? domain.getTenantId().value() : null,
                domain.getUserId() != null ? domain.getUserId().value() : null,
                domain.getEmail().value(),
                domain.getPurpose() != null ? domain.getPurpose().name() : "EMAIL_VERIFICATION",
                domain.getCodeHash().value(),
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
        OtpPurpose purpose = OtpPurpose.EMAIL_VERIFICATION;
        if (entity.getPurpose() != null) {
            try {
                purpose = OtpPurpose.valueOf(entity.getPurpose());
            } catch (IllegalArgumentException ignored) {
            }
        }
        return OtpVerification.reconstitute(
                new OtpVerificationId(entity.getId()),
                entity.getTenantId() != null ? new TenantId(entity.getTenantId()) : null,
                entity.getUserId() != null ? new UserId(entity.getUserId()) : null,
                new Email(entity.getEmail()),
                purpose,
                new OtpCodeHash(entity.getCodeHash()),
                entity.getAttempts(),
                entity.isVerified(),
                entity.getExpiresAt(),
                entity.getCreatedAt()
        );
    }
}
