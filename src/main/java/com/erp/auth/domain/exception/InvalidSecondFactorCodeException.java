package com.erp.auth.domain.exception;

/**
 * Thrown when a second-factor authentication code is invalid: it does not match
 * the enrolled secret, has expired, or has already been consumed.
 */
public class InvalidSecondFactorCodeException extends DomainException {

    public InvalidSecondFactorCodeException() {
        super("AUTH_SECOND_FACTOR_INVALID", "El codigo de segundo factor no es valido");
    }

    public InvalidSecondFactorCodeException(String message) {
        super("AUTH_SECOND_FACTOR_INVALID", message);
    }
}
