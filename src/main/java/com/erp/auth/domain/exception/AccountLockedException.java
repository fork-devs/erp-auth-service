package com.erp.auth.domain.exception;

import java.time.Instant;

public class AccountLockedException extends DomainException {
    private final Instant lockedUntil;

    public AccountLockedException(Instant lockedUntil) {
        super("AUTH_ACCOUNT_LOCKED", "La cuenta se encuentra temporalmente bloqueada por múltiples intentos fallidos.");
        this.lockedUntil = lockedUntil;
    }

    public Instant getLockedUntil() {
        return lockedUntil;
    }
}
