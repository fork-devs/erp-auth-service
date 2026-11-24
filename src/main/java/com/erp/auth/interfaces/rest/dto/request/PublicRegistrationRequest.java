package com.erp.auth.interfaces.rest.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.util.UUID;

public record PublicRegistrationRequest(
        @NotBlank @Email String email,
        @NotBlank @Size(min = 12) String password,
        @NotBlank String fullName,
        @NotBlank String accountType,
        UUID tenantId
) {
}
