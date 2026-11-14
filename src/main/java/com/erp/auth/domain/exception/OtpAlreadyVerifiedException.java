package com.erp.auth.domain.exception;

public class OtpAlreadyVerifiedException extends DomainException {
    private static final long serialVersionUID = 1L;

    public OtpAlreadyVerifiedException(String message) {
        super("iam.error.otp.already_verified", message);
    }

    public OtpAlreadyVerifiedException(String message, Throwable cause) {
        super("iam.error.otp.already_verified", message, cause);
    }
}
