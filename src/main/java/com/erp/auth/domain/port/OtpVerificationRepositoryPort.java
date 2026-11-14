package com.erp.auth.domain.port;

import com.erp.auth.domain.model.OtpVerification;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.domain.valueobject.OtpVerificationId;

import java.util.Optional;

public interface OtpVerificationRepositoryPort {
    OtpVerification save(OtpVerification otpVerification);
    Optional<OtpVerification> findLatestByEmail(Email email);
    Optional<OtpVerification> findById(OtpVerificationId id);
    void incrementAttempts(OtpVerificationId id);
    void invalidateAllPendingByEmail(Email email);
}
