package com.erp.auth.domain.exception;

import com.erp.auth.domain.model.RoleCode;

/**
 * Se lanza cuando un principal intenta conceder un rol que su propio rol no
 * le permite conceder, o cuando su rol no le permite crear usuarios.
 *
 * <p>Ver docs/doc-estado-implementacion.md, hallazgo P0 5.1.
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
