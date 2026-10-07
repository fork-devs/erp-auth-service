package com.erp.auth.domain.port;

import com.erp.auth.domain.model.RefreshToken;

import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepositoryPort {
    RefreshToken save(RefreshToken refreshToken);
    Optional<RefreshToken> findByTokenHash(String tokenHash);
    void revokeByTokenHash(String tokenHash);
    void revokeAllByUserId(UUID userId);
}
