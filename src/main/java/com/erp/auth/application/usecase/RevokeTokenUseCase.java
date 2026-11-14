package com.erp.auth.application.usecase;

import com.erp.auth.domain.valueobject.TenantId;
import com.erp.auth.domain.valueobject.UserId;

import java.util.UUID;

public interface RevokeTokenUseCase {
    void revokeToken(String refreshToken);
    default void revokeAllByUserId(UserId userId, TenantId tenantId) {
        throw new UnsupportedOperationException("Multi-tenant safety: revokeAllByUserId requires implementation");
    }

    default void revokeAllUserTokens(UUID userId) {
        throw new UnsupportedOperationException("Multi-tenant safety: revokeAllUserTokens requires TenantId");
    }
}
