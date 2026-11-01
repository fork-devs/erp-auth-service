package com.erp.auth.domain.exception;

public class InvalidOtpException extends DomainException {
    public InvalidOtpException(String message) {
        super("iam.error.otp.invalid", message);
    }
}
