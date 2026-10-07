package com.erp.auth.domain.exception;

public class TokenRevokedException extends DomainException {
    public TokenRevokedException() {
        super("AUTH_TOKEN_REVOKED", "El token ha sido revocado o ya no es válido.");
    }
}
