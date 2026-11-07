package com.erp.auth.domain.exception;

public class UserNotFoundException extends DomainException {
    private static final long serialVersionUID = 1L;

    public UserNotFoundException(String identifier) {
        super("AUTH_USER_NOT_FOUND", "No se encontró el usuario: " + sanitize(identifier));
    }

    public UserNotFoundException(String identifier, Throwable cause) {
        super("AUTH_USER_NOT_FOUND", "No se encontró el usuario: " + sanitize(identifier), cause);
    }
}
