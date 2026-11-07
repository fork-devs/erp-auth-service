package com.erp.auth.domain;

import com.erp.auth.domain.model.RefreshToken;
import com.erp.auth.domain.model.TokenHash;
import com.erp.auth.domain.valueobject.TenantId;
import com.erp.auth.domain.valueobject.UserId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Domain - RefreshToken Test")
class RefreshTokenTest {

    private static final String VALID_HEX = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    @Test
    @DisplayName("Should create active RefreshToken with Value Objects")
    void shouldCreateActiveRefreshToken() {
        UserId userId = UserId.generate();
        TenantId tenantId = TenantId.generate();
        TokenHash tokenHash = TokenHash.of(VALID_HEX);
        Instant expiresAt = Instant.now().plus(7, ChronoUnit.DAYS);

        RefreshToken token = RefreshToken.create(userId, tenantId, tokenHash, expiresAt);

        assertNotNull(token.getId());
        assertEquals(userId, token.getUserIdVO());
        assertEquals(userId.getValue(), token.getUserId());
        assertEquals(tenantId, token.getTenantIdVO());
        assertEquals(tenantId.getValue(), token.getTenantId());
        assertEquals(tokenHash, token.getTokenHashVO());
        assertEquals(tokenHash.getValue(), token.getTokenHash());
        assertFalse(token.isRevoked());
        assertTrue(token.isValid());
    }

    @Test
    @DisplayName("Should revoke active token successfully")
    void shouldRevokeToken() {
        RefreshToken token = RefreshToken.create(
                UserId.generate(),
                TenantId.generate(),
                TokenHash.of(VALID_HEX),
                Instant.now().plus(1, ChronoUnit.DAYS)
        );

        assertTrue(token.isValid());
        token.revoke();
        assertTrue(token.isRevoked());
        assertFalse(token.isValid());
    }

    @Test
    @DisplayName("Should detect expired token as invalid")
    void shouldDetectExpiredToken() {
        RefreshToken token = RefreshToken.create(
                UserId.generate(),
                TenantId.generate(),
                TokenHash.of(VALID_HEX),
                Instant.now().minus(1, ChronoUnit.HOURS)
        );

        assertFalse(token.isRevoked());
        assertFalse(token.isValid());
    }

    @Test
    @DisplayName("Should throw IllegalArgumentException when required fields are null")
    void shouldThrowWhenRequiredFieldsNull() {
        assertThrows(IllegalArgumentException.class, () ->
                new RefreshToken(null, UserId.generate(), TenantId.generate(), TokenHash.of(VALID_HEX), Instant.now(), false, null));
        assertThrows(IllegalArgumentException.class, () ->
                new RefreshToken(UUID.randomUUID(), null, TenantId.generate(), TokenHash.of(VALID_HEX), Instant.now(), false, null));
        assertThrows(IllegalArgumentException.class, () ->
                new RefreshToken(UUID.randomUUID(), UserId.generate(), null, TokenHash.of(VALID_HEX), Instant.now(), false, null));
        assertThrows(IllegalArgumentException.class, () ->
                new RefreshToken(UUID.randomUUID(), UserId.generate(), TenantId.generate(), null, Instant.now(), false, null));
    }
}
