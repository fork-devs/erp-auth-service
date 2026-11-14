package com.erp.auth.domain.exception;

public class TokenExpiredException extends DomainException {
    private static final long serialVersionUID = 1L;

    public TokenExpiredException() {
        super("AUTH_TOKEN_EXPIRED", "El token ha expirado. Por favor inicie sesión nuevamente.");
    }

    public TokenExpiredException(String message) {
        super("AUTH_TOKEN_EXPIRED", message);
    }

    public TokenExpiredException(String message, Throwable cause) {
        super("AUTH_TOKEN_EXPIRED", message, cause);
    }
}
