package com.erp.auth.interfaces.rest.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.UUID;

public record RefreshTokenRequest(
        @NotBlank(message = "{validation.auth.refresh-token.token.not-blank}")
        String refreshToken,

        @NotNull(message = "{validation.auth.refresh-token.tenant-id.not-null}")
        UUID tenantId
) {}
