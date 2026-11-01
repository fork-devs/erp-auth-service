package com.erp.auth.domain.exception;

public class OtpExpiredException extends DomainException {
    public OtpExpiredException(String message) {
        super("iam.error.otp.expired", message);
    }
}
