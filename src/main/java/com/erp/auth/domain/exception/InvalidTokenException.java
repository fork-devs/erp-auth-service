package com.erp.auth.domain.exception;

public class InvalidTokenException extends DomainException {
    public InvalidTokenException(String message) {
        super("AUTH_INVALID_TOKEN", message);
    }

    public InvalidTokenException() {
        this("El token proporcionado es inválido o no existe.");
    }
}
