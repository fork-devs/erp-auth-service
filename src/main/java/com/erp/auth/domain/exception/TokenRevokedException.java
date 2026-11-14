package com.erp.auth.domain.exception;

public class TokenRevokedException extends DomainException {
    private static final long serialVersionUID = 1L;

    public TokenRevokedException() {
        super("AUTH_TOKEN_REVOKED", "El token ha sido revocado o ya no es válido.");
    }

    public TokenRevokedException(String message) {
        super("AUTH_TOKEN_REVOKED", message);
    }

    public TokenRevokedException(String message, Throwable cause) {
        super("AUTH_TOKEN_REVOKED", message, cause);
    }
}
