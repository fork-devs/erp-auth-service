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
 * Password reset operations are atomic.
 *
 * <p>Marking the token as used, updating the password hash, and revoking
 * existing sessions constitute three distinct writes. Without a common transaction
 * boundary, a failure between them leaves the token consumed while the password
 * remains unchanged, requiring the user to request a new token.
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
            String crudo = tokenSignerPort.generatePasswordResetToken(usuario().getId());
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
