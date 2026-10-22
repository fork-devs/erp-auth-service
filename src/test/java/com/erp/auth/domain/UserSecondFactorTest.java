package com.erp.auth.domain;

import com.erp.auth.domain.model.Role;
import com.erp.auth.domain.model.RoleCode;
import com.erp.auth.domain.model.User;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.domain.valueobject.PasswordHash;
import com.erp.auth.domain.valueobject.TenantId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * El segundo factor se habilita y se deshabilita en el dominio.
 *
 * <p>El campo mfaEnabled se fijaba en falso al construir el usuario y no
 * habia ninguna manera de cambiarlo: el segundo factor no existia.
 */
class UserSecondFactorTest {

    @Test
    @DisplayName("Un usuario recien creado tiene el segundo factor deshabilitado")
    void unUsuarioNuevoTieneElSegundoFactorDeshabilitado() {
        User user = usuario();

        assertFalse(user.isMfaEnabled(),
                "El segundo factor no se habilita solo: exige un enrolamiento confirmado");
    }

    @Test
    @DisplayName("La operacion de habilitacion lo activa")
    void laOperacionDeHabilitacionLoActiva() {
        User user = usuario();

        user.enableSecondFactor();

        assertTrue(user.isMfaEnabled());
    }

    @Test
    @DisplayName("El segundo factor se puede deshabilitar")
    void elSegundoFactorSePuedeDeshabilitar() {
        User user = usuario();
        user.enableSecondFactor();

        user.disableSecondFactor();

        assertFalse(user.isMfaEnabled());
    }

    private User usuario() {
        return User.create(
                new TenantId(UUID.randomUUID()),
                Email.of("mfa@taller.pe"),
                PasswordHash.of("$2a$12$hash"),
                "Usuario",
                Set.of(new Role(UUID.randomUUID(), RoleCode.ASESOR, "Asesor")));
    }
}
