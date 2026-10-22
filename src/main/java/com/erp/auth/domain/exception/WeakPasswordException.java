package com.erp.auth.domain.exception;

/**
 * La contrasena no cumple la politica: es demasiado corta, o es de las mas
 * usadas.
 */
public class WeakPasswordException extends DomainException {

    public WeakPasswordException(String motivo) {
        super("AUTH_WEAK_PASSWORD", motivo);
    }
}
