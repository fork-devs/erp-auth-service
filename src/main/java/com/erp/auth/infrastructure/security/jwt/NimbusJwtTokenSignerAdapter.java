package com.erp.auth.infrastructure.security.jwt;

import com.erp.auth.domain.model.User;
import com.erp.auth.domain.port.TokenSignerPort;
import com.erp.auth.infrastructure.security.crypto.RsaKeyPairManager;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Component
public class NimbusJwtTokenSignerAdapter implements TokenSignerPort {

    private final RsaKeyPairManager keyPairManager;
    private final String issuer;
    private final Duration accessTokenDuration;
    private final Duration refreshTokenDuration;
    private final Duration passwordResetTokenDuration;
    private final SecureRandom secureRandom = new SecureRandom();

    public NimbusJwtTokenSignerAdapter(
            RsaKeyPairManager keyPairManager,
            @Value("${erp.security.jwt.issuer:https://auth.erp-automotriz.com}") String issuer,
            @Value("${erp.security.jwt.access-token-expiration-minutes:15}") long accessTokenExpirationMinutes,
            @Value("${erp.security.jwt.refresh-token-expiration-days:7}") long refreshTokenExpirationDays,
            @Value("${erp.security.jwt.password-reset-token-expiration-minutes:30}") long passwordResetTokenExpirationMinutes) {
        this.keyPairManager = keyPairManager;
        this.issuer = issuer;
        this.accessTokenDuration = Duration.ofMinutes(accessTokenExpirationMinutes);
        this.refreshTokenDuration = Duration.ofDays(refreshTokenExpirationDays);
        this.passwordResetTokenDuration = Duration.ofMinutes(passwordResetTokenExpirationMinutes);
    }

    @Override
    public String generateAccessToken(User user) {
        try {
            Instant now = Instant.now();
            Instant expiry = now.plus(accessTokenDuration);

            List<String> roleNames = user.getRoles().stream()
                    .map(r -> r.getCode().name())
                    .collect(Collectors.toList());

            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .issuer(issuer)
                    .subject(user.getId().toString())
                    .claim("tenant_id", user.getTenantId().getValue().toString())
                    .claim("email", user.getEmail().getValue())
                    .claim("name", user.getFullName())
                    .claim("roles", roleNames)
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(expiry))
                    .build();

            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .keyID(keyPairManager.getKeyId())
                    .build();

            SignedJWT signedJWT = new SignedJWT(header, claimsSet);
            RSASSASigner signer = new RSASSASigner(keyPairManager.getPrivateKey());
            signedJWT.sign(signer);

            return signedJWT.serialize();
        } catch (Exception e) {
            throw new IllegalStateException("Error al generar y firmar el token JWT", e);
        }
    }

    @Override
    public String generateRandomTokenString() {
        byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    @Override
    public String hashToken(String rawToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encodedhash = digest.digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(encodedhash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Algoritmo SHA-256 no disponible", e);
        }
    }

    @Override
    public Duration getAccessTokenDuration() {
        return accessTokenDuration;
    }

    @Override
    public Duration getRefreshTokenDuration() {
        return refreshTokenDuration;
    }

    @Override
    public Duration getPasswordResetTokenDuration() {
        return passwordResetTokenDuration;
    }

    @Override
    public Map<String, Object> getJwksPublicKeySet() {
        return keyPairManager.getJwksPublicKeySet();
    }
}
