package com.erp.auth.domain.exception;

public class TokenExpiredException extends DomainException {
    public TokenExpiredException() {
        super("AUTH_TOKEN_EXPIRED", "El token ha expirado. Por favor inicie sesión nuevamente.");
    }
}
