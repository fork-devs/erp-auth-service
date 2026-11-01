package com.erp.auth.application.dto.command;

import java.util.UUID;

public record LoginCommand(
        String email,
        String password,
        UUID tenantId,
        /**
         * Second-factor authentication code. Mandatory when the account has 2FA enabled;
         * ignored otherwise.
         */
        String secondFactorCode
) {
    public LoginCommand(String email, String password, UUID tenantId) {
        this(email, password, tenantId, null);
    }
}
