package com.erp.auth.interfaces.rest.dto.request;

import com.erp.auth.domain.model.RoleCode;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Alta de un usuario del taller.
 *
 * <p>NO acepta el identificador de taller: el sistema lo deduce del
 * principal autenticado, de modo que el cliente no puede crear usuarios en
 * otro taller.
 *
 * <p>El rol que se quiere conceder se declara de forma acotada, con un unico
 * valor del catalogo. El sistema solo lo asigna si el rol del principal tiene
 * permiso para concederlo; en caso contrario, la peticion se rechaza.
 */
public record RegisterUserRequest(
        @NotBlank(message = "El correo electrónico es obligatorio")
        @Email(message = "Formato de correo inválido")
        String email,

        @NotBlank(message = "La contraseña es obligatoria")
        @Size(min = 12, message = "La contraseña debe tener al menos 12 caracteres")
        String password,

        @NotBlank(message = "El nombre completo es obligatorio")
        String fullName,

        RoleCode role
) {
}
