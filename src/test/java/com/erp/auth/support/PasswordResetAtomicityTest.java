package com.erp.auth.support;

import com.erp.auth.application.dto.command.ResetPasswordCommand;
import com.erp.auth.application.service.PasswordResetService;
import com.erp.auth.domain.model.PasswordResetToken;
import com.erp.auth.infrastructure.persistence.rls.TenantContextScope;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * El restablecimiento de la contrasena es atomico.
 *
 * <p>Marcar el token como usado, cambiar la contrasena y revocar las
 * sesiones son tres escrituras. Sin un limite transaccional comun, un fallo
 * entre ellas deja al usuario con el token consumido y la contrasena sin
 * cambiar: un estado del que no se puede salir sin pedir un token nuevo.
 *
 * <p>Ver docs/doc-estado-implementacion.md, hallazgo P0 5.3.
 */
class PasswordResetAtomicityTest extends AbstractAuthAtomicityTest {

    @Autowired
    private PasswordResetService passwordResetService;

    @Test
    void unFalloAlCambiarLaContrasenaNoDejaElTokenConsumido() {
        String tokenCrudo = tokenDeRestablecimiento();
        String hash = tokenSignerPort.hashToken(tokenCrudo);

        falloAlEscribirElUsuario(new RuntimeException("no se puede escribir el usuario"));

        assertThrows(RuntimeException.class, () -> restablecer(tokenCrudo));

        PasswordResetToken token = tokenDeRestablecimiento(hash);
        assertTrue(token.isValid(),
                "El token de restablecimiento no debe quedar consumido si la contrasena no llego a cambiarse");
    }

    private void restablecer(String tokenCrudo) {
        try (TenantContextScope scope = TenantContextScope.forTenant(TALLER)) {
            passwordResetService.resetPassword(new ResetPasswordCommand(tokenCrudo, "NuevaContrasena1!", TALLER));
        }
    }

    private String tokenDeRestablecimiento() {
        try (TenantContextScope scope = TenantContextScope.forTenant(TALLER)) {
            String crudo = tokenSignerPort.generateRandomTokenString();
            String hash = tokenSignerPort.hashToken(crudo);
            unitOfWork.runInTransaction(() -> passwordResetTokenRepositoryPort.save(
                    PasswordResetToken.create(usuario().getId(), TALLER, hash, Instant.now().plusSeconds(3600))));
            return crudo;
        }
    }

    private PasswordResetToken tokenDeRestablecimiento(String hash) {
        try (TenantContextScope scope = TenantContextScope.forTenant(TALLER)) {
            return passwordResetTokenRepositoryPort.findByTokenHashAndTenantId(hash, TALLER).orElseThrow();
        }
    }
}
