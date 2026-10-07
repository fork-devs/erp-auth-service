package com.erp.auth.domain;

import com.erp.auth.domain.model.Role;
import com.erp.auth.domain.model.RoleCode;
import com.erp.auth.domain.model.User;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.domain.valueobject.PasswordHash;
import com.erp.auth.domain.valueobject.TenantId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class UserDomainTest {

    @Test
    @DisplayName("Debe bloquear la cuenta tras alcanzar 5 intentos fallidos (QA-5)")
    void shouldLockAccountAfterFiveFailedAttempts() {
        TenantId tenantId = TenantId.generate();
        Email email = Email.of("mecanico@taller.pe");
        PasswordHash passwordHash = PasswordHash.of("$2a$12$hashedPasswordExample");
        Role role = Role.create(RoleCode.MECANICO, "Técnico");

        User user = User.create(tenantId, email, passwordHash, "Carlos Méndez", Set.of(role));

        assertFalse(user.isAccountLocked(), "La cuenta debe iniciar desbloqueada");
        assertEquals(0, user.getFailedAttempts());

        // Simular 4 intentos fallidos
        for (int i = 1; i <= 4; i++) {
            user.recordFailedAttempt(5, Duration.ofMinutes(15));
            assertEquals(i, user.getFailedAttempts());
            assertFalse(user.isAccountLocked(), "No debe bloquearse antes del 5to intento");
        }

        // 5to intento fallido
        user.recordFailedAttempt(5, Duration.ofMinutes(15));
        assertEquals(5, user.getFailedAttempts());
        assertTrue(user.isAccountLocked(), "La cuenta debe estar bloqueada al 5to intento");
        assertNotNull(user.getLockedUntil());
    }

    @Test
    @DisplayName("Login exitoso debe reiniciar el contador de intentos fallidos a cero")
    void shouldResetFailedAttemptsOnSuccessfulLogin() {
        TenantId tenantId = TenantId.generate();
        Email email = Email.of("asesor@taller.pe");
        PasswordHash passwordHash = PasswordHash.of("$2a$12$hashedPasswordExample");

        User user = User.create(tenantId, email, passwordHash, "Ana Rojas", Set.of());
        user.recordFailedAttempt(5, Duration.ofMinutes(15));
        user.recordFailedAttempt(5, Duration.ofMinutes(15));
        assertEquals(2, user.getFailedAttempts());

        user.recordSuccessfulLogin();
        assertEquals(0, user.getFailedAttempts());
        assertNull(user.getLockedUntil());
        assertFalse(user.isAccountLocked());
    }

    @Test
    @DisplayName("Debe validar formato correcto de Email y rechazar inválidos")
    void shouldValidateEmailFormat() {
        assertDoesNotThrow(() -> Email.of("contacto@tallerautomotriz.com"));
        assertThrows(IllegalArgumentException.class, () -> Email.of("email-invalido-sin-arroba"));
        assertThrows(IllegalArgumentException.class, () -> Email.of(""));
    }
}
