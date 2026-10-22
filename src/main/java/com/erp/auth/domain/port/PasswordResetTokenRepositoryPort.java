package com.erp.auth.domain.port;

import com.erp.auth.domain.model.PasswordResetToken;

import java.util.Optional;
import java.util.UUID;

public interface PasswordResetTokenRepositoryPort {
    PasswordResetToken save(PasswordResetToken token);
    Optional<PasswordResetToken> findByTokenHash(String tokenHash);
    Optional<PasswordResetToken> findByTokenHashAndTenantId(String tokenHash, UUID tenantId);
    void invalidateAllByUserId(UUID userId);
}
