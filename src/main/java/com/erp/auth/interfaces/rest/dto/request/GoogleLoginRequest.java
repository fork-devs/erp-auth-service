package com.erp.auth.interfaces.rest.dto.request;

import jakarta.validation.constraints.NotBlank;
import java.util.UUID;

public record GoogleLoginRequest(
        @NotBlank(message = "idToken es obligatorio")
        String idToken,
        UUID tenantId
) {}
