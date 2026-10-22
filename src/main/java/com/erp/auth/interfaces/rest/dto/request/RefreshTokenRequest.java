package com.erp.auth.interfaces.rest.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.UUID;

public record RefreshTokenRequest(
        @NotBlank(message = "El token de actualización es obligatorio")
        String refreshToken,

        @NotNull(message = "El identificador de taller es obligatorio")
        UUID tenantId
) {}
