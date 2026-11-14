package com.erp.auth.domain.exception;

/**
 * Thrown when a password does not comply with the security policy: it is too short
 * or belongs to the list of most commonly used passwords.
 */
public class WeakPasswordException extends DomainException {
    private static final long serialVersionUID = 1L;

    public WeakPasswordException(String motivo) {
        super("AUTH_WEAK_PASSWORD", motivo);
    }

    public WeakPasswordException(String motivo, Throwable cause) {
        super("AUTH_WEAK_PASSWORD", motivo, cause);
    }
}
