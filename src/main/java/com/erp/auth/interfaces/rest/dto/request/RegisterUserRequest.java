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
        @NotBlank(message = "{validation.auth.register-user.email.not-blank}")
        @Email(message = "{validation.auth.register-user.email.format}")
        String email,

        @NotBlank(message = "{validation.auth.register-user.password.not-blank}")
        @Size(min = 12, message = "{validation.auth.register-user.password.size}")
        String password,

        @NotBlank(message = "{validation.auth.register-user.full-name.not-blank}")
        String fullName,

        RoleCode role
) {
}
