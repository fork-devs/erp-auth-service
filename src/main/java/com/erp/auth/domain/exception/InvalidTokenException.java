package com.erp.auth.domain.exception;

public class InvalidTokenException extends DomainException {
    private static final long serialVersionUID = 1L;

    public InvalidTokenException(String message) {
        super("AUTH_INVALID_TOKEN", message);
    }

    public InvalidTokenException(String message, Throwable cause) {
        super("AUTH_INVALID_TOKEN", message, cause);
    }

    public InvalidTokenException() {
        this("El token proporcionado es inválido o no existe.");
    }
}
