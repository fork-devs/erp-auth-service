package com.erp.auth.application.dto.command;

import com.erp.auth.domain.model.RoleCode;
import com.erp.auth.domain.valueobject.TenantId;

import java.util.Set;

/**
 * User registration within a workshop tenant.
 *
 * <p>The tenant ID is not declared arbitrarily by the client: it is resolved from
 * the authenticated principal and attached to the command. The requested role is
 * validated against the matrix of roles the actor is authorized to grant.
 */
public record RegisterUserCommand(
        TenantId tenantId,
        String email,
        String password,
        String fullName,
        Set<RoleCode> requestedRoles,
        RoleCode actorRole
) {
}
