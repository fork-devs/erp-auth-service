package com.erp.auth.application.usecase;

import java.util.UUID;

public interface RevokeTokenUseCase {
    void revokeToken(String refreshToken);
    void revokeAllUserTokens(UUID userId);
}
