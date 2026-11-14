package com.erp.auth.domain.exception;

public class OtpExpiredException extends DomainException {
    private static final long serialVersionUID = 1L;

    public OtpExpiredException(String message) {
        super("iam.error.otp.expired", message);
    }

    public OtpExpiredException(String message, Throwable cause) {
        super("iam.error.otp.expired", message, cause);
    }
}
