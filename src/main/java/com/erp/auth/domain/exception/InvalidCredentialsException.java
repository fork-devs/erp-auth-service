package com.erp.auth.domain.exception;

public class InvalidCredentialsException extends DomainException {
    public InvalidCredentialsException(String message) {
        super("AUTH_INVALID_CREDENTIALS", message);
    }

    public InvalidCredentialsException() {
        this("Credenciales inválidas. Por favor verifique su correo y contraseña.");
    }
}
