package com.erp.auth.support;

import com.erp.auth.application.dto.command.RefreshTokenCommand;
import com.erp.auth.application.service.RefreshTokenService;
import com.erp.auth.domain.model.RefreshToken;
import com.erp.auth.infrastructure.persistence.rls.TenantContextScope;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * La rotacion del token de refresco es atomica.
 *
 * <p>Revocar el token anterior y emitir el nuevo son dos escrituras. Sin un
 * limite transaccional comun, un fallo entre ellas deja al usuario sin
 * sesion: el token viejo ya revocado y el nuevo nunca creado.
 *
 * <p>Ver docs/doc-estado-implementacion.md, hallazgo P0 5.3.
 */
class RefreshTokenRotationAtomicityTest extends AbstractAuthAtomicityTest {

    @Autowired
    private RefreshTokenService refreshTokenService;

    @Test
    void unFalloAlEmitirElTokenNuevoRevierteLaRevocacionDelAnterior() {
        String tokenCrudo = tokenDeRefresco();
        String hash = tokenSignerPort.hashToken(tokenCrudo);

        falloAlEscribirElToken(new RuntimeException("no se puede escribir el token"));

        assertThrows(RuntimeException.class, () -> renovar(tokenCrudo));

        RefreshToken anterior = tokenRevocado(hash);
        assertFalse(anterior.isRevoked(),
                "La revocacion del token anterior debe revertirse con ella: el usuario conserva su sesion");
    }

    private void renovar(String tokenCrudo) {
        try (TenantContextScope scope = TenantContextScope.forTenant(TALLER)) {
            refreshTokenService.refreshToken(new RefreshTokenCommand(tokenCrudo, TALLER));
        }
    }

    private String tokenDeRefresco() {
        try (TenantContextScope scope = TenantContextScope.forTenant(TALLER)) {
            String crudo = tokenSignerPort.generateRandomTokenString();
            String hash = tokenSignerPort.hashToken(crudo);
            unitOfWork.runInTransaction(() -> refreshTokenRepositoryPort.save(
                    RefreshToken.create(usuario().getId(), TALLER, hash, Instant.now().plusSeconds(3600))));
            return crudo;
        }
    }

    private RefreshToken tokenRevocado(String hash) {
        try (TenantContextScope scope = TenantContextScope.forTenant(TALLER)) {
            return refreshTokenRepositoryPort.findByTokenHashAndTenantId(hash, TALLER).orElseThrow();
        }
    }
}
