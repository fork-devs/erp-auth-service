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
 * Refresh token rotation is atomic.
 *
 * <p>Revoking the previous token and issuing a new one are two writes. Without
 * a shared transaction boundary, a failure between them leaves the user stranded:
 * the old token is revoked while the replacement is never created.
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
            String crudo = tokenSignerPort.generateRefreshToken(usuario());
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
