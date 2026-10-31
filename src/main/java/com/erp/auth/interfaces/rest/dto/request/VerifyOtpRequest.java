package com.erp.auth.interfaces.rest.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record VerifyOtpRequest(
        @NotBlank(message = "El correo es obligatorio")
        @Email(message = "El formato del correo es inválido")
        String email,

        @NotBlank(message = "El código es obligatorio")
        @Pattern(regexp = "^[0-9]{6}$", message = "El código OTP debe ser de 6 dígitos numéricos")
        String code
) {}
