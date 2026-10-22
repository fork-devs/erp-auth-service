package com.erp.auth.interfaces.rest.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.UUID;

public record ForgotPasswordRequest(
        @NotBlank(message = "El correo electrónico es obligatorio")
        @Email(message = "Formato de correo inválido")
        String email,

        @NotNull(message = "El identificador de taller es obligatorio")
        UUID tenantId
) {}
