package com.erp.auth.infrastructure.security.oauth;

import com.erp.auth.domain.exception.GoogleAuthenticationException;
import com.erp.auth.domain.model.GoogleTokenPayload;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Infrastructure - NimbusGoogleTokenVerifierAdapter Hardening Test")
class NimbusGoogleTokenVerifierAdapterTest {

    private static final String CLIENT_ID = "google-client-id-12345.apps.googleusercontent.com";
    private static final String ISSUER = "https://accounts.google.com";

    private RSAKey testRsaKey;
    private RSAKey attackerRsaKey;
    private NimbusGoogleTokenVerifierAdapter adapter;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);

        KeyPair validPair = gen.generateKeyPair();
        testRsaKey = new RSAKey.Builder((RSAPublicKey) validPair.getPublic())
                .privateKey((RSAPrivateKey) validPair.getPrivate())
                .keyID("valid-key-id")
                .build();

        KeyPair attackerPair = gen.generateKeyPair();
        attackerRsaKey = new RSAKey.Builder((RSAPublicKey) attackerPair.getPublic())
                .privateKey((RSAPrivateKey) attackerPair.getPrivate())
                .keyID("attacker-key-id")
                .build();

        // Configure hermetic JWT processor using the valid public key JWKS
        ConfigurableJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        JWKSet jwkSet = new JWKSet(testRsaKey.toPublicJWK());
        JWSKeySelector<SecurityContext> keySelector =
                new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, new ImmutableJWKSet<>(jwkSet));
        processor.setJWSKeySelector(keySelector);

        adapter = new NimbusGoogleTokenVerifierAdapter(CLIENT_ID, processor);
    }

    @Test
    @DisplayName("Should successfully verify a genuine Google ID token")
    void shouldVerifyValidGoogleToken() throws Exception {
        String token = createToken(
                ISSUER,
                CLIENT_ID,
                "mechanic@driveos.pe",
                true,
                "Carlos Mecanico",
                "google-sub-999",
                Instant.now().plus(1, ChronoUnit.HOURS),
                testRsaKey
        );

        GoogleTokenPayload payload = adapter.verifyToken(token);

        assertNotNull(payload);
        assertEquals("mechanic@driveos.pe", payload.email());
        assertEquals("Carlos Mecanico", payload.fullName());
        assertEquals("google-sub-999", payload.subject());
    }

    @Test
    @DisplayName("Should reject forged signature from untrusted key (Account Takeover Prevention)")
    void shouldRejectForgedSignature() throws Exception {
        String forgedToken = createToken(
                ISSUER,
                CLIENT_ID,
                "victim@driveos.pe",
                true,
                "Victim User",
                "google-sub-111",
                Instant.now().plus(1, ChronoUnit.HOURS),
                attackerRsaKey // Attacker key NOT present in Google JWKS
        );

        GoogleAuthenticationException ex = assertThrows(
                GoogleAuthenticationException.class,
                () -> adapter.verifyToken(forgedToken)
        );
        assertTrue(ex.getMessage().contains("Cryptographic verification failed"));
    }

    @Test
    @DisplayName("Should reject token with invalid issuer")
    void shouldRejectInvalidIssuer() throws Exception {
        String token = createToken(
                "https://malicious-issuer.com",
                CLIENT_ID,
                "user@driveos.pe",
                true,
                "User",
                "sub-1",
                Instant.now().plus(1, ChronoUnit.HOURS),
                testRsaKey
        );

        GoogleAuthenticationException ex = assertThrows(
                GoogleAuthenticationException.class,
                () -> adapter.verifyToken(token)
        );
        assertTrue(ex.getMessage().contains("Invalid Google ID token issuer"));
    }

    @Test
    @DisplayName("Should reject token with audience not matching configured client ID")
    void shouldRejectMismatchedAudience() throws Exception {
        String token = createToken(
                ISSUER,
                "unauthorized-client-id",
                "user@driveos.pe",
                true,
                "User",
                "sub-1",
                Instant.now().plus(1, ChronoUnit.HOURS),
                testRsaKey
        );

        GoogleAuthenticationException ex = assertThrows(
                GoogleAuthenticationException.class,
                () -> adapter.verifyToken(token)
        );
        assertTrue(ex.getMessage().contains("does not match configured client_id"));
    }

    @Test
    @DisplayName("Should reject token when email_verified is false or missing")
    void shouldRejectUnverifiedEmail() throws Exception {
        String token = createToken(
                ISSUER,
                CLIENT_ID,
                "user@driveos.pe",
                false, // email NOT verified
                "User",
                "sub-1",
                Instant.now().plus(1, ChronoUnit.HOURS),
                testRsaKey
        );

        GoogleAuthenticationException ex = assertThrows(
                GoogleAuthenticationException.class,
                () -> adapter.verifyToken(token)
        );
        assertTrue(ex.getMessage().contains("Google account email is not verified"));
    }

    @Test
    @DisplayName("Should reject expired token")
    void shouldRejectExpiredToken() throws Exception {
        String token = createToken(
                ISSUER,
                CLIENT_ID,
                "user@driveos.pe",
                true,
                "User",
                "sub-1",
                Instant.now().minus(1, ChronoUnit.HOURS), // Expired
                testRsaKey
        );

        GoogleAuthenticationException ex = assertThrows(
                GoogleAuthenticationException.class,
                () -> adapter.verifyToken(token)
        );
        assertTrue(ex.getMessage().toLowerCase().contains("expired"));
    }

    @Test
    @DisplayName("Should fail closed when configured client ID is missing or empty")
    void shouldFailClosedWhenClientIdNotConfigured() throws Exception {
        NimbusGoogleTokenVerifierAdapter unconfiguredAdapter =
                new NimbusGoogleTokenVerifierAdapter("", null);

        assertThrows(GoogleAuthenticationException.class, () -> unconfiguredAdapter.verifyToken("any-token"));
    }

    private String createToken(
            String issuer,
            String audience,
            String email,
            boolean emailVerified,
            String name,
            String subject,
            Instant expiresAt,
            RSAKey signingKey) throws Exception {

        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .audience(audience)
                .jwtID(UUID.randomUUID().toString())
                .issueTime(new Date())
                .expirationTime(Date.from(expiresAt))
                .claim("email", email)
                .claim("email_verified", emailVerified);

        if (name != null) {
            builder.claim("name", name);
        }
        if (subject != null) {
            builder.subject(subject);
        }

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(signingKey.getKeyID()).build(),
                builder.build()
        );
        signedJWT.sign(new RSASSASigner(signingKey.toRSAPrivateKey()));
        return signedJWT.serialize();
    }
}
