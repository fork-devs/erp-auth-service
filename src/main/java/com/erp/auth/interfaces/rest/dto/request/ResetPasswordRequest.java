package com.erp.auth.interfaces.rest.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.util.UUID;

public record ResetPasswordRequest(
        @NotBlank(message = "{validation.auth.reset-password.token.not-blank}")
        String token,

        @NotBlank(message = "{validation.auth.reset-password.new-password.not-blank}")
        @Size(min = 6, message = "{validation.auth.reset-password.new-password.size}")
        String newPassword,

        @NotNull(message = "{validation.auth.reset-password.tenant-id.not-null}")
        UUID tenantId
) {}
