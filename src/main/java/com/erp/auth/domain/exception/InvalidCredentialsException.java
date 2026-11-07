package com.erp.auth.domain.exception;

public class InvalidCredentialsException extends DomainException {
    private static final long serialVersionUID = 1L;

    public InvalidCredentialsException(String message) {
        super("AUTH_INVALID_CREDENTIALS", message);
    }

    public InvalidCredentialsException(String message, Throwable cause) {
        super("AUTH_INVALID_CREDENTIALS", message, cause);
    }

    public InvalidCredentialsException() {
        this("Credenciales inválidas. Por favor verifique su correo y contraseña.");
    }
}
