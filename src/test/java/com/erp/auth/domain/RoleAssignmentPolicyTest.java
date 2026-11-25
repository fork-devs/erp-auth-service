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
 * <p>Supports canonical English roles and legacy Spanish aliases normalization.
 */
class RoleAssignmentPolicyTest {

    @Test
    void elSuperadministradorConcedeCualquierRol() {
        assertEquals(EnumSet.allOf(RoleCode.class), RoleAssignmentPolicy.assignableRolesFor(RoleCode.SUPERADMIN));
    }

    @Test
    void elAdministradorDeTallerConcedeSoloLosRolesDeSuAmbito() {
        assertEquals(EnumSet.of(
                RoleCode.WORKSHOP_ADMIN,
                RoleCode.BRANCH_MANAGER,
                RoleCode.SERVICE_ADVISOR,
                RoleCode.SECRETARY,
                RoleCode.TECHNICIAN,
                RoleCode.CUSTOMER
        ), RoleAssignmentPolicy.assignableRolesFor(RoleCode.WORKSHOP_ADMIN));
    }

    @Test
    void branchManagerGrantsOperationalBranchRolesOnly() {
        assertEquals(EnumSet.of(
                RoleCode.SERVICE_ADVISOR,
                RoleCode.SECRETARY,
                RoleCode.TECHNICIAN,
                RoleCode.CUSTOMER
        ), RoleAssignmentPolicy.assignableRolesFor(RoleCode.BRANCH_MANAGER));
        assertFalse(RoleAssignmentPolicy.canAssign(RoleCode.BRANCH_MANAGER, RoleCode.WORKSHOP_ADMIN));
        assertFalse(RoleAssignmentPolicy.canAssign(RoleCode.BRANCH_MANAGER, RoleCode.BRANCH_MANAGER));
    }

    @Test
    void secretaryCannotGrantAnyRole() {
        assertTrue(RoleAssignmentPolicy.assignableRolesFor(RoleCode.SECRETARY).isEmpty());
        assertNull(RoleAssignmentPolicy.defaultRoleFor(RoleCode.SECRETARY));
    }

    @Test
    void unAsesorNoPuedeConcederNingunRol() {
        assertTrue(RoleAssignmentPolicy.assignableRolesFor(RoleCode.SERVICE_ADVISOR).isEmpty());
        assertNull(RoleAssignmentPolicy.defaultRoleFor(RoleCode.SERVICE_ADVISOR));
    }

    @Test
    void unMecanicoNoPuedeConcederNingunRol() {
        assertTrue(RoleAssignmentPolicy.assignableRolesFor(RoleCode.TECHNICIAN).isEmpty());
    }

    @Test
    void noSePuedeConcederUnRolSuperiorAlPropio() {
        assertFalse(RoleAssignmentPolicy.canAssign(RoleCode.WORKSHOP_ADMIN, RoleCode.SUPERADMIN));
        assertFalse(RoleAssignmentPolicy.canAssign(RoleCode.SERVICE_ADVISOR, RoleCode.TECHNICIAN));
    }

    @Test
    void sePuedeConcederUnRolIgualODentroDelAmbito() {
        assertTrue(RoleAssignmentPolicy.canAssign(RoleCode.WORKSHOP_ADMIN, RoleCode.TECHNICIAN));
        assertTrue(RoleAssignmentPolicy.canAssign(RoleCode.WORKSHOP_ADMIN, RoleCode.SERVICE_ADVISOR));
        assertTrue(RoleAssignmentPolicy.canAssign(RoleCode.SUPERADMIN, RoleCode.SUPERADMIN));
    }

    @Test
    void sinRolDeActorNoSeConcedeNada() {
        assertEquals(Set.of(), RoleAssignmentPolicy.assignableRolesFor(null));
        assertFalse(RoleAssignmentPolicy.canAssign(null, RoleCode.SERVICE_ADVISOR));
    }

    @Test
    void normalizesEnglishRoleAliases() {
        assertEquals(RoleCode.SUPERADMIN, RoleCode.fromString("ADMIN"));
        assertEquals(RoleCode.SUPERADMIN, RoleCode.fromString("role_superadmin"));
        assertEquals(RoleCode.WORKSHOP_ADMIN, RoleCode.fromString("OWNER"));
        assertEquals(RoleCode.WORKSHOP_ADMIN, RoleCode.fromString("role_workshop_admin"));
        assertEquals(RoleCode.BRANCH_MANAGER, RoleCode.fromString("ROLE_BRANCH_MANAGER"));
        assertEquals(RoleCode.SERVICE_ADVISOR, RoleCode.fromString("ROLE_SERVICE_ADVISOR"));
        assertEquals(RoleCode.SECRETARY, RoleCode.fromString("RECEPTIONIST"));
        assertEquals(RoleCode.SECRETARY, RoleCode.fromString("role_receptionist"));
        assertEquals(RoleCode.TECHNICIAN, RoleCode.fromString("ROLE_TECHNICIAN"));
        assertEquals(RoleCode.CUSTOMER, RoleCode.fromString("USER"));
    }
}
