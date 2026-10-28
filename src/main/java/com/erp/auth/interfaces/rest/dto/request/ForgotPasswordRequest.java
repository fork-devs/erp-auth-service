package com.erp.auth.interfaces.rest.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.UUID;

public record ForgotPasswordRequest(
        @NotBlank(message = "{validation.auth.forgot-password.email.not-blank}")
        @Email(message = "{validation.auth.forgot-password.email.format}")
        String email,

        @NotNull(message = "{validation.auth.forgot-password.tenant-id.not-null}")
        UUID tenantId
) {}
