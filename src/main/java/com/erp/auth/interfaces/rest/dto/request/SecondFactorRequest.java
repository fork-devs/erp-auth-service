package com.erp.auth.interfaces.rest.dto.request;

import jakarta.validation.constraints.NotBlank;

/**
 * Confirmacion del enrolamiento del segundo factor.
 *
 * <p>El codigo es el que el usuario ve en su aplicacion autenticadora. El
 * secreto NO se pide aqui, y menos se devuelve: se entrega por el canal de
 * notificacion.
 */
public record SecondFactorRequest(
        @NotBlank(message = "El codigo de segundo factor es obligatorio")
        String code
) {
}
