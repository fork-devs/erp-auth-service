package com.erp.auth.domain;

import com.erp.auth.domain.model.RoleAssignmentPolicy;
import com.erp.auth.domain.model.RoleCode;
import org.junit.jupiter.api.Test;

import java.util.EnumSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Matriz de roles concedibles: nadie concede un privilegio superior al suyo.
 *
 * <p>Ver docs/doc-estado-implementacion.md, hallazgo P0 5.1.
 */
class RoleAssignmentPolicyTest {

    @Test
    void elSuperadministradorConcedeCualquierRol() {
        assertEquals(EnumSet.allOf(RoleCode.class), RoleAssignmentPolicy.assignableRolesFor(RoleCode.SUPERADMIN));
    }

    @Test
    void elAdministradorDeTallerConcedeSoloLosRolesDeSuAmbito() {
        assertEquals(EnumSet.of(RoleCode.ADMIN_TALLER, RoleCode.ASESOR, RoleCode.MECANICO),
                RoleAssignmentPolicy.assignableRolesFor(RoleCode.ADMIN_TALLER));
    }

    @Test
    void unAsesorNoPuedeConcederNingunRol() {
        assertTrue(RoleAssignmentPolicy.assignableRolesFor(RoleCode.ASESOR).isEmpty());
        assertNull(RoleAssignmentPolicy.defaultRoleFor(RoleCode.ASESOR));
    }

    @Test
    void unMecanicoNoPuedeConcederNingunRol() {
        assertTrue(RoleAssignmentPolicy.assignableRolesFor(RoleCode.MECANICO).isEmpty());
    }

    @Test
    void noSePuedeConcederUnRolSuperiorAlPropio() {
        assertFalse(RoleAssignmentPolicy.canAssign(RoleCode.ADMIN_TALLER, RoleCode.SUPERADMIN));
        assertFalse(RoleAssignmentPolicy.canAssign(RoleCode.ASESOR, RoleCode.MECANICO));
    }

    @Test
    void sePuedeConcederUnRolIgualODentroDelAmbito() {
        assertTrue(RoleAssignmentPolicy.canAssign(RoleCode.ADMIN_TALLER, RoleCode.ADMIN_TALLER));
        assertTrue(RoleAssignmentPolicy.canAssign(RoleCode.ADMIN_TALLER, RoleCode.ASESOR));
        assertTrue(RoleAssignmentPolicy.canAssign(RoleCode.SUPERADMIN, RoleCode.SUPERADMIN));
    }

    @Test
    void sinRolDeActorNoSeConcedeNada() {
        assertEquals(Set.of(), RoleAssignmentPolicy.assignableRolesFor(null));
        assertFalse(RoleAssignmentPolicy.canAssign(null, RoleCode.ASESOR));
    }
}
