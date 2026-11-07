package com.erp.auth.domain.exception;

public class GoogleAuthenticationException extends DomainException {
    private static final long serialVersionUID = 1L;

    public GoogleAuthenticationException(String message) {
        super("iam.error.google.authenticationFailed", message);
    }

    public GoogleAuthenticationException(String message, Throwable cause) {
        super("iam.error.google.authenticationFailed", message, cause);
    }
}
