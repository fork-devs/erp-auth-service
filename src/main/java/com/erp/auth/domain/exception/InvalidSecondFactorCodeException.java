package com.erp.auth.domain.exception;

/**
 * El codigo de segundo factor no es valido: no corresponde al secreto
 * enrolado, ha caducado, o ya se ha usado.
 */
public class InvalidSecondFactorCodeException extends DomainException {

    public InvalidSecondFactorCodeException() {
        super("AUTH_SECOND_FACTOR_INVALID", "El codigo de segundo factor no es valido");
    }

    public InvalidSecondFactorCodeException(String message) {
        super("AUTH_SECOND_FACTOR_INVALID", message);
    }
}
