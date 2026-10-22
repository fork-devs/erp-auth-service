package com.erp.auth.domain.model;

import java.util.EnumSet;
import java.util.Set;

/**
 * Matriz de roles que un principal puede conceder al crear un usuario.
 *
 * <p>El principio es que nadie puede conceder un privilegio superior al
 * suyo: un SUPERADMIN puede conceder cualquier rol, un ADMIN_TALLER solo
 * puede conceder roles de su ambito, y un ASESOR o un MECANICO no pueden
 * crear usuarios en absoluto.
 *
 * <p>Ver docs/doc-estado-implementacion.md, hallazgo P0 5.1.
 */
public final class RoleAssignmentPolicy {

    private RoleAssignmentPolicy() {
    }

    /**
     * Roles que el actor puede conceder. Un conjunto vacio significa que el
     * actor no puede crear usuarios.
     */
    public static Set<RoleCode> assignableRolesFor(RoleCode actorRole) {
        if (actorRole == null) {
            return Set.of();
        }
        return switch (actorRole) {
            case SUPERADMIN -> EnumSet.allOf(RoleCode.class);
            case ADMIN_TALLER -> EnumSet.of(RoleCode.ADMIN_TALLER, RoleCode.ASESOR, RoleCode.MECANICO);
            case ASESOR, MECANICO -> Set.of();
        };
    }

    /**
     * Rol por defecto que se concede cuando el actor puede crear usuarios y
     * no se pide uno concreto.
     */
    public static RoleCode defaultRoleFor(RoleCode actorRole) {
        if (!assignableRolesFor(actorRole).isEmpty()) {
            return RoleCode.ASESOR;
        }
        return null;
    }

    public static boolean canAssign(RoleCode actorRole, RoleCode requestedRole) {
        return requestedRole != null && assignableRolesFor(actorRole).contains(requestedRole);
    }
}
