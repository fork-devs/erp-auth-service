package com.erp.auth.domain.exception;

public class UserAlreadyExistsException extends DomainException {
    private static final long serialVersionUID = 1L;

    public UserAlreadyExistsException(String email) {
        super("AUTH_USER_ALREADY_EXISTS", "Ya existe un usuario registrado con el correo: " + sanitize(email));
    }

    public UserAlreadyExistsException(String email, Throwable cause) {
        super("AUTH_USER_ALREADY_EXISTS", "Ya existe un usuario registrado con el correo: " + sanitize(email), cause);
    }
}
