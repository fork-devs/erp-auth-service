package com.erp.auth.interfaces.rest.dto.request;

import com.erp.auth.domain.model.RoleCode;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * User registration request for a workshop tenant.
 *
 * <p>The tenant ID is not accepted from the request body: the system resolves it
 * from the authenticated principal to prevent cross-tenant user creation.
 *
 * <p>The requested role is evaluated against the assignable role matrix of the caller's role;
 * unauthorized role grants are rejected.
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
