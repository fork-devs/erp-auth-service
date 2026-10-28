package com.erp.auth.domain.model;

import java.util.EnumSet;
import java.util.Set;

/**
 * Role assignment matrix specifying which roles a principal may grant when creating a user.
 *
 * <p>The guiding principle is that no actor can grant privileges exceeding their own:
 * a SUPERADMIN can grant any role, an ADMIN_TALLER can only grant roles within their workshop
 * scope, and an ASESOR or MECANICO cannot create users at all.
 *
 * <p>See docs/doc-estado-implementacion.md, finding P0 5.1.
 */
public final class RoleAssignmentPolicy {

    private RoleAssignmentPolicy() {
    }

    /**
     * Returns the roles that the actor is authorized to grant. An empty set indicates
     * that the actor is not allowed to create users.
     *
     * @param actorRole the role of the acting principal
     * @return the set of assignable roles
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
     * Default role granted when the actor is authorized to create users and no specific
     * role was requested.
     *
     * @param actorRole the role of the acting principal
     * @return the default role, or null if the actor cannot create users
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
