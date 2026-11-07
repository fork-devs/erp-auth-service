package com.erp.auth.domain.exception;

public class InvalidOtpException extends DomainException {
    private static final long serialVersionUID = 1L;

    public InvalidOtpException(String message) {
        super("iam.error.otp.invalid", message);
    }

    public InvalidOtpException(String message, Throwable cause) {
        super("iam.error.otp.invalid", message, cause);
    }
}
