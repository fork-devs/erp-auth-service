package com.erp.auth.application.dto.command;

import java.util.UUID;

public record LoginCommand(
        String email,
        String password,
        UUID tenantId,
        /**
         * Codigo del segundo factor. Obligatorio cuando la cuenta lo tiene
         * habilitado; se ignora cuando no lo tiene.
         */
        String secondFactorCode
) {
    public LoginCommand(String email, String password, UUID tenantId) {
        this(email, password, tenantId, null);
    }
}
