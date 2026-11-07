package com.erp.auth.infrastructure.security.oauth;

import com.erp.auth.domain.exception.GoogleAuthenticationException;
import com.erp.auth.domain.model.GoogleTokenPayload;
import com.erp.auth.domain.port.GoogleTokenVerifierPort;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.Date;
import java.util.List;
import java.util.Set;

@Component
public class NimbusGoogleTokenVerifierAdapter implements GoogleTokenVerifierPort {

    private static final String GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs";
    private static final Set<String> ALLOWED_ISSUERS = Set.of("https://accounts.google.com", "accounts.google.com");

    private final String configuredClientId;
    private final ConfigurableJWTProcessor<SecurityContext> jwtProcessor;

    public NimbusGoogleTokenVerifierAdapter(
            @Value("${google.client.id:${spring.security.oauth2.client.registration.google.client-id:}}") String configuredClientId) {
        this(configuredClientId, createDefaultProcessor(GOOGLE_JWKS_URL));
    }

    @Autowired(required = false)
    public NimbusGoogleTokenVerifierAdapter(
            @Value("${google.client.id:${spring.security.oauth2.client.registration.google.client-id:}}") String configuredClientId,
            ConfigurableJWTProcessor<SecurityContext> jwtProcessor) {
        this.configuredClientId = configuredClientId != null ? configuredClientId.trim() : "";
        this.jwtProcessor = jwtProcessor != null ? jwtProcessor : createDefaultProcessor(GOOGLE_JWKS_URL);
    }

    private static ConfigurableJWTProcessor<SecurityContext> createDefaultProcessor(String jwksUrl) {
        try {
            ConfigurableJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
            JWKSource<SecurityContext> jwkSource = new RemoteJWKSet<>(URI.create(jwksUrl).toURL());
            JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, jwkSource);
            processor.setJWSKeySelector(keySelector);
            return processor;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to configure Google JWKS processor", e);
        }
    }

    @Override
    public GoogleTokenPayload verifyToken(String idToken) {
        if (idToken == null || idToken.isBlank()) {
            throw new GoogleAuthenticationException("Google ID token cannot be null or empty");
        }

        if (configuredClientId.isEmpty()) {
            throw new GoogleAuthenticationException("Google client ID is not configured on the server");
        }

        JWTClaimsSet claims;
        try {
            claims = jwtProcessor.process(idToken, null);
        } catch (Exception e) {
            throw new GoogleAuthenticationException("Cryptographic verification failed for Google ID token: " + e.getMessage(), e);
        }

        // 1. Verify issuer
        String issuer = claims.getIssuer();
        if (issuer == null || !ALLOWED_ISSUERS.contains(issuer)) {
            throw new GoogleAuthenticationException("Invalid Google ID token issuer: " + issuer);
        }

        // 2. Verify audience matches configured client ID
        List<String> audience = claims.getAudience();
        if (audience == null || !audience.contains(configuredClientId)) {
            throw new GoogleAuthenticationException("Google ID token audience does not match configured client_id: " + configuredClientId);
        }

        // 3. Verify expiration
        Date expirationTime = claims.getExpirationTime();
        if (expirationTime == null) {
            throw new GoogleAuthenticationException("Google ID token missing mandatory exp claim");
        }
        if (new Date().after(expirationTime)) {
            throw new GoogleAuthenticationException("Google ID token has expired");
        }

        // 4. Verify email_verified == true
        Boolean emailVerified = (Boolean) claims.getClaim("email_verified");
        if (emailVerified == null || !emailVerified) {
            throw new GoogleAuthenticationException("Google account email is not verified");
        }

        // 5. Extract strict identity without fallbacks
        try {
            String email = claims.getStringClaim("email");
            if (email == null || email.isBlank()) {
                throw new GoogleAuthenticationException("Google ID token does not contain an email claim");
            }

            String subject = claims.getSubject();
            if (subject == null || subject.isBlank()) {
                throw new GoogleAuthenticationException("Google ID token missing mandatory sub claim (no fallback permitted)");
            }

            String name = claims.getStringClaim("name");
            if (name == null || name.isBlank()) {
                throw new GoogleAuthenticationException("Google ID token missing mandatory name claim (no fallback permitted)");
            }

            return new GoogleTokenPayload(email, name, subject);
        } catch (java.text.ParseException e) {
            throw new GoogleAuthenticationException("Invalid Google ID token claims format: " + e.getMessage(), e);
        }
    }
}
