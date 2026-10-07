package com.erp.auth.domain.exception;

public class UserAlreadyExistsException extends DomainException {
    public UserAlreadyExistsException(String email) {
        super("AUTH_USER_ALREADY_EXISTS", "Ya existe un usuario registrado con el correo: " + email);
    }
}
