package com.erp.auth.domain;

import com.erp.auth.domain.model.PasswordResetToken;
import com.erp.auth.domain.model.TokenHash;
import com.erp.auth.domain.valueobject.TenantId;
import com.erp.auth.domain.valueobject.UserId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Domain - PasswordResetToken Test")
class PasswordResetTokenTest {

    private static final String VALID_HEX = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    @Test
    @DisplayName("Should create active PasswordResetToken with Value Objects")
    void shouldCreateActivePasswordResetToken() {
        UserId userId = UserId.generate();
        TenantId tenantId = TenantId.generate();
        TokenHash tokenHash = TokenHash.of(VALID_HEX);
        Instant expiresAt = Instant.now().plus(1, ChronoUnit.HOURS);

        PasswordResetToken token = PasswordResetToken.create(userId, tenantId, tokenHash, expiresAt);

        assertNotNull(token.getId());
        assertEquals(userId, token.getUserIdVO());
        assertEquals(userId.getValue(), token.getUserId());
        assertEquals(tenantId, token.getTenantIdVO());
        assertEquals(tenantId.getValue(), token.getTenantId());
        assertEquals(tokenHash, token.getTokenHashVO());
        assertEquals(tokenHash.getValue(), token.getTokenHash());
        assertNull(token.getUsedAt());
        assertTrue(token.isValid());
    }

    @Test
    @DisplayName("Should mark token as used and prevent second use")
    void shouldMarkAsUsed() {
        PasswordResetToken token = PasswordResetToken.create(
                UserId.generate(),
                TenantId.generate(),
                TokenHash.of(VALID_HEX),
                Instant.now().plus(1, ChronoUnit.HOURS)
        );

        assertTrue(token.isValid());
        token.markAsUsed();
        assertNotNull(token.getUsedAt());
        assertFalse(token.isValid());

        assertThrows(IllegalStateException.class, token::markAsUsed);
    }

    @Test
    @DisplayName("Should detect expired reset token as invalid")
    void shouldDetectExpiredResetToken() {
        PasswordResetToken token = PasswordResetToken.create(
                UserId.generate(),
                TenantId.generate(),
                TokenHash.of(VALID_HEX),
                Instant.now().minus(1, ChronoUnit.HOURS)
        );

        assertFalse(token.isValid());
    }

    @Test
    @DisplayName("Should throw IllegalArgumentException when required fields are null")
    void shouldThrowWhenRequiredFieldsNull() {
        assertThrows(IllegalArgumentException.class, () ->
                new PasswordResetToken(null, UserId.generate(), TenantId.generate(), TokenHash.of(VALID_HEX), Instant.now(), null, null));
        assertThrows(IllegalArgumentException.class, () ->
                new PasswordResetToken(UUID.randomUUID(), null, TenantId.generate(), TokenHash.of(VALID_HEX), Instant.now(), null, null));
        assertThrows(IllegalArgumentException.class, () ->
                new PasswordResetToken(UUID.randomUUID(), UserId.generate(), null, TokenHash.of(VALID_HEX), Instant.now(), null, null));
        assertThrows(IllegalArgumentException.class, () ->
                new PasswordResetToken(UUID.randomUUID(), UserId.generate(), TenantId.generate(), null, Instant.now(), null, null));
    }
}
