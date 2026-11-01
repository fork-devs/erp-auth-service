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
 * Assignable role matrix test: no actor may grant privileges exceeding their own.
 *
 * <p>Supports canonical English roles and legacy Spanish aliases.
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

        assertEquals(EnumSet.of(
                RoleCode.WORKSHOP_ADMIN,
                RoleCode.SERVICE_ADVISOR,
                RoleCode.TECHNICIAN,
                RoleCode.CUSTOMER,
                RoleCode.ADMIN_TALLER,
                RoleCode.ASESOR,
                RoleCode.MECANICO
        ), RoleAssignmentPolicy.assignableRolesFor(RoleCode.WORKSHOP_ADMIN));
    }

    @Test
    void unAsesorNoPuedeConcederNingunRol() {
        assertTrue(RoleAssignmentPolicy.assignableRolesFor(RoleCode.ASESOR).isEmpty());
        assertNull(RoleAssignmentPolicy.defaultRoleFor(RoleCode.ASESOR));
        assertTrue(RoleAssignmentPolicy.assignableRolesFor(RoleCode.SERVICE_ADVISOR).isEmpty());
        assertNull(RoleAssignmentPolicy.defaultRoleFor(RoleCode.SERVICE_ADVISOR));
    }

    @Test
    void unMecanicoNoPuedeConcederNingunRol() {
        assertTrue(RoleAssignmentPolicy.assignableRolesFor(RoleCode.MECANICO).isEmpty());
        assertTrue(RoleAssignmentPolicy.assignableRolesFor(RoleCode.TECHNICIAN).isEmpty());
    }

    @Test
    void noSePuedeConcederUnRolSuperiorAlPropio() {
        assertFalse(RoleAssignmentPolicy.canAssign(RoleCode.ADMIN_TALLER, RoleCode.SUPERADMIN));
        assertFalse(RoleAssignmentPolicy.canAssign(RoleCode.WORKSHOP_ADMIN, RoleCode.SUPERADMIN));
        assertFalse(RoleAssignmentPolicy.canAssign(RoleCode.ASESOR, RoleCode.MECANICO));
        assertFalse(RoleAssignmentPolicy.canAssign(RoleCode.SERVICE_ADVISOR, RoleCode.TECHNICIAN));
    }

    @Test
    void sePuedeConcederUnRolIgualODentroDelAmbito() {
        assertTrue(RoleAssignmentPolicy.canAssign(RoleCode.ADMIN_TALLER, RoleCode.ADMIN_TALLER));
        assertTrue(RoleAssignmentPolicy.canAssign(RoleCode.ADMIN_TALLER, RoleCode.ASESOR));
        assertTrue(RoleAssignmentPolicy.canAssign(RoleCode.WORKSHOP_ADMIN, RoleCode.TECHNICIAN));
        assertTrue(RoleAssignmentPolicy.canAssign(RoleCode.WORKSHOP_ADMIN, RoleCode.SERVICE_ADVISOR));
        assertTrue(RoleAssignmentPolicy.canAssign(RoleCode.SUPERADMIN, RoleCode.SUPERADMIN));
    }

    @Test
    void sinRolDeActorNoSeConcedeNada() {
        assertEquals(Set.of(), RoleAssignmentPolicy.assignableRolesFor(null));
        assertFalse(RoleAssignmentPolicy.canAssign(null, RoleCode.ASESOR));
        assertFalse(RoleAssignmentPolicy.canAssign(null, RoleCode.SERVICE_ADVISOR));
    }
}
