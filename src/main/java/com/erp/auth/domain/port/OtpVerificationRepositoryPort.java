package com.erp.auth.domain.port;

import com.erp.auth.domain.model.OtpVerification;
import com.erp.auth.domain.valueobject.Email;

import java.util.Optional;

public interface OtpVerificationRepositoryPort {
    OtpVerification save(OtpVerification otpVerification);
    Optional<OtpVerification> findLatestByEmail(Email email);
}
