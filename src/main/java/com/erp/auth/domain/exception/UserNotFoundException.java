package com.erp.auth.domain.exception;

public class UserNotFoundException extends DomainException {
    public UserNotFoundException(String identifier) {
        super("AUTH_USER_NOT_FOUND", "No se encontró el usuario: " + identifier);
    }
}
