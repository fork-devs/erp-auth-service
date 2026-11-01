package com.erp.auth.support;

import com.erp.auth.application.dto.command.LoginCommand;
import com.erp.auth.application.service.AuthenticateUserService;
import com.erp.auth.infrastructure.persistence.rls.TenantContextScope;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * User login is atomic.
 *
 * <p>Resetting the failed attempts counter and issuing the refresh token
 * are two writes. Without a common transaction boundary, a failure between
 * them would leave the counter reset to zero without issuing the token,
 * potentially resetting lockout limits inappropriately.
 */
class LoginAtomicityTest extends AbstractAuthAtomicityTest {

    @Autowired
    private AuthenticateUserService authenticateUserService;

    @Test
    void unFalloAlPersistirElRefreshTokenNoDejaElContadorDeIntentosRestablecido() {
        // A failed attempt leaves the counter at 1.
        assertThrows(RuntimeException.class, () -> iniciarSesion("ContrasenaEquivocada1!"));
        assertEquals(1, usuario().getFailedAttempts(), "El intento fallido debe quedar registrado");

        // Now a successful login whose token fails to be persisted.
        // The counter must NOT be reset: the authentication did not complete.
        falloAlEscribirElToken(new RuntimeException("no se puede escribir el token"));

        assertThrows(RuntimeException.class, () -> iniciarSesion(CONTRASENA));

        assertEquals(1, usuario().getFailedAttempts(),
                "El contador de intentos no debe quedar restablecido si la operacion no llego a confirmarse");
    }

    private void iniciarSesion(String contrasena) {
        try (TenantContextScope scope = TenantContextScope.forTenant(TALLER)) {
            authenticateUserService.authenticate(new LoginCommand(correo, contrasena, TALLER));
        }
    }
}
