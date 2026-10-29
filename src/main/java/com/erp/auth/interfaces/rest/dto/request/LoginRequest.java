package com.erp.auth.interfaces.rest.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.util.UUID;

public record LoginRequest(
        @NotBlank(message = "{validation.auth.login.email.not-blank}")
        @Email(message = "{validation.auth.login.email.format}")
        String email,

        @NotBlank(message = "{validation.auth.login.password.not-blank}")
        @Size(min = 6, message = "{validation.auth.login.password.size}")
        String password,

        @NotNull(message = "{validation.auth.login.tenant-id.not-null}")
        UUID tenantId
) {}
