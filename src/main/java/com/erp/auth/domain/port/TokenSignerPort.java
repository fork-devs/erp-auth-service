package com.erp.auth.domain.port;

import com.erp.auth.domain.model.User;

import java.time.Duration;
import java.util.Map;

public interface TokenSignerPort {
    String generateAccessToken(User user);
    String generateRandomTokenString();
    String hashToken(String rawToken);
    Duration getAccessTokenDuration();
    Duration getRefreshTokenDuration();
    Duration getPasswordResetTokenDuration();
    Map<String, Object> getJwksPublicKeySet();
}
