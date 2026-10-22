package com.erp.auth.support;

import com.erp.auth.application.dto.command.LoginCommand;
import com.erp.auth.application.service.AuthenticateUserService;
import com.erp.auth.infrastructure.persistence.rls.TenantContextScope;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * El inicio de sesion es atomico.
 *
 * <p>Restablecer el contador de intentos fallidos y emitir el refresh token
 * son dos escrituras. Sin un limite transaccional comun, un fallo entre
 * ellas deja el contador a cero y el acceso sin.token: el sistema afirma un
 * acceso que nunca llego a darle, y la cuenta vuelve a estar disponible para
 * intentos ilimitados.
 *
 * <p>Ver docs/doc-estado-implementacion.md, hallazgo P0 5.3.
 */
class LoginAtomicityTest extends AbstractAuthAtomicityTest {

    @Autowired
    private AuthenticateUserService authenticateUserService;

    @Test
    void unFalloAlPersistirElRefreshTokenNoDejaElContadorDeIntentosRestablecido() {
        // Un intento fallido deja el contador en 1.
        assertThrows(RuntimeException.class, () -> iniciarSesion("ContrasenaEquivocada1!"));
        assertEquals(1, usuario().getFailedAttempts(), "El intento fallido debe quedar registrado");

        // Ahora un inicio de sesion correcto cuyo token no llega a escribirse.
        // El contador NO debe restablecerse: el acceso no llego a completarse.
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
