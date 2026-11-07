package com.erp.auth.infrastructure.security.jwt;

import com.erp.auth.domain.model.Role;
import com.erp.auth.domain.model.RoleCode;
import com.erp.auth.domain.model.TokenIdentity;
import com.erp.auth.domain.model.User;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.domain.valueobject.PasswordHash;
import com.erp.auth.domain.valueobject.TenantId;
import com.erp.auth.infrastructure.security.crypto.RsaKeyPairManager;
import com.erp.auth.support.TestKeyMaterial;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Infrastructure - NimbusJwtTokenSignerAdapter Hardening Test")
class NimbusJwtTokenSignerAdapterTest {

    private static final String ISSUER = "https://auth.test.erp-automotriz.com";
    private static final String AUDIENCE = "erp-api-gateway";

    private RsaKeyPairManager keyPairManager;
    private Clock fixedClock;
    private NimbusJwtTokenSignerAdapter signer;

    @BeforeEach
    void setUp() {
        keyPairManager = new RsaKeyPairManager(
                TestKeyMaterial.privateKeyPem(), TestKeyMaterial.publicKeyPem(), "", "");
        fixedClock = Clock.fixed(Instant.parse("2026-11-07T12:00:00Z"), ZoneOffset.UTC);
        signer = new NimbusJwtTokenSignerAdapter(keyPairManager, ISSUER, AUDIENCE, 15, 7, 30, fixedClock);
    }

    @Test
    @DisplayName("Constructor should reject non-positive durations with IllegalArgumentException")
    void constructorShouldRejectNonPositiveDurations() {
        assertThrows(IllegalArgumentException.class, () ->
                new NimbusJwtTokenSignerAdapter(keyPairManager, ISSUER, AUDIENCE, 0, 7, 30, fixedClock));
        assertThrows(IllegalArgumentException.class, () ->
                new NimbusJwtTokenSignerAdapter(keyPairManager, ISSUER, AUDIENCE, 15, -1, 30, fixedClock));
        assertThrows(IllegalArgumentException.class, () ->
                new NimbusJwtTokenSignerAdapter(keyPairManager, ISSUER, AUDIENCE, 15, 7, 0, fixedClock));
    }

    @Test
    @DisplayName("extractIdentity should extract claims successfully when token has valid exp, jti and sub")
    void extractIdentityShouldSucceedWithValidToken() {
        User user = User.create(
                TenantId.generate(),
                Email.of("test@taller.pe"),
                PasswordHash.of("hash"),
                "Test User",
                Set.of(new Role(UUID.randomUUID(), RoleCode.WORKSHOP_ADMIN, "Admin"))
        );

        String token = signer.generateAccessToken(user);
        TokenIdentity identity = signer.extractIdentity(token);

        assertNotNull(identity);
        assertEquals(user.getId(), identity.userId());
        assertNotNull(identity.tokenId());
        assertNotNull(identity.expiresAt());
    }

    @Test
    @DisplayName("extractIdentity should throw IllegalStateException when exp is missing (no fallback to now)")
    void extractIdentityShouldThrowWhenExpMissing() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .audience(AUDIENCE)
                .jwtID(UUID.randomUUID().toString())
                .subject(UUID.randomUUID().toString())
                .issueTime(new Date())
                // No expirationTime!
                .build();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(keyPairManager.getKeyId())
                .build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new RSASSASigner(keyPairManager.getPrivateKey()));

        assertThrows(IllegalStateException.class, () -> signer.extractIdentity(jwt.serialize()));
    }
}
