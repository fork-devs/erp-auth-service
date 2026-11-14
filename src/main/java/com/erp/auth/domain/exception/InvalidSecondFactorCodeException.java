package com.erp.auth.domain.exception;

public class InvalidSecondFactorCodeException extends DomainException {
    private static final long serialVersionUID = 1L;

    public InvalidSecondFactorCodeException() {
        super("AUTH_SECOND_FACTOR_INVALID", "El codigo de segundo factor no es valido");
    }

    public InvalidSecondFactorCodeException(String message) {
        super("AUTH_SECOND_FACTOR_INVALID", message);
    }

    public InvalidSecondFactorCodeException(String message, Throwable cause) {
        super("AUTH_SECOND_FACTOR_INVALID", message, cause);
    }
}
