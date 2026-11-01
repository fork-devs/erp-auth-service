package com.erp.auth.interfaces.rest.dto.request;

import com.erp.auth.domain.model.RoleCode;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record InviteUserRequest(
        @NotBlank(message = "{validation.auth.register-user.email.not-blank}")
        @Email(message = "{validation.auth.register-user.email.format}")
        String email,

        @NotBlank(message = "{validation.auth.register-user.full-name.not-blank}")
        String fullName,

        @NotNull(message = "El rol es obligatorio")
        RoleCode role
) {}
