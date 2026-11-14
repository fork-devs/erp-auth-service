package com.erp.auth.domain.exception;

import com.erp.auth.domain.model.RoleCode;

public class RoleNotAssignableException extends DomainException {
    private static final long serialVersionUID = 1L;

    public RoleNotAssignableException(RoleCode actorRole) {
        super("AUTH_ROLE_NOT_ASSIGNABLE",
                "El rol " + actorRole + " no tiene permiso para crear usuarios.");
    }

    public RoleNotAssignableException(RoleCode actorRole, RoleCode requestedRole) {
        super("AUTH_ROLE_NOT_ASSIGNABLE",
                "El rol " + actorRole + " no tiene permiso para conceder el rol " + requestedRole + ".");
    }

    public RoleNotAssignableException(String message, Throwable cause) {
        super("AUTH_ROLE_NOT_ASSIGNABLE", message, cause);
    }
}
