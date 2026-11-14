package com.erp.auth.domain.exception;

public class OtpMaxAttemptsExceededException extends DomainException {
    private static final long serialVersionUID = 1L;

    public OtpMaxAttemptsExceededException(String message) {
        super("iam.error.otp.maxAttemptsExceeded", message);
    }

    public OtpMaxAttemptsExceededException(String message, Throwable cause) {
        super("iam.error.otp.maxAttemptsExceeded", message, cause);
    }
}
