package com.erp.auth.domain.exception;

import com.erp.auth.domain.model.RoleCode;

/**
 * Thrown when an actor attempts to grant a role that their own role does not
 * permit them to assign, or when their role does not allow user creation at all.
 *
 * <p>See docs/doc-estado-implementacion.md, finding P0 5.1.
 */
public class RoleNotAssignableException extends DomainException {

    public RoleNotAssignableException(RoleCode actorRole) {
        super("AUTH_ROLE_NOT_ASSIGNABLE",
                "El rol " + actorRole + " no tiene permiso para crear usuarios.");
    }

    public RoleNotAssignableException(RoleCode actorRole, RoleCode requestedRole) {
        super("AUTH_ROLE_NOT_ASSIGNABLE",
                "El rol " + actorRole + " no tiene permiso para conceder el rol " + requestedRole + ".");
    }
}
