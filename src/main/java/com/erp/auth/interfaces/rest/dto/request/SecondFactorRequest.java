package com.erp.auth.interfaces.rest.dto.request;

import jakarta.validation.constraints.NotBlank;

/**
 * Confirmation request for second-factor authentication enrollment.
 *
 * <p>Contains the code from the user's authenticator app.
 * Secrets are never transmitted in request bodies.
 */
public record SecondFactorRequest(
        @NotBlank(message = "El codigo de segundo factor es obligatorio")
        String code
) {
}
