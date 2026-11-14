package com.erp.auth.domain.exception;

public class OtpRateLimitExceededException extends DomainException {
    private static final long serialVersionUID = 1L;

    public OtpRateLimitExceededException(String message) {
        super("iam.error.otp.rate_limit_exceeded", message);
    }

    public OtpRateLimitExceededException(String message, Throwable cause) {
        super("iam.error.otp.rate_limit_exceeded", message, cause);
    }
}
