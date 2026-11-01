package com.erp.auth.interfaces.rest.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record UpdateEmailRequest(
        @NotBlank(message = "El nuevo correo es obligatorio")
        @Email(message = "El formato del correo es inválido")
        String email
) {}
