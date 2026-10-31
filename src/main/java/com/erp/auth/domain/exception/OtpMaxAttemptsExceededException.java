package com.erp.auth.domain.exception;

public class OtpMaxAttemptsExceededException extends DomainException {
    public OtpMaxAttemptsExceededException(String message) {
        super("iam.error.otp.maxAttemptsExceeded", message);
    }
}
