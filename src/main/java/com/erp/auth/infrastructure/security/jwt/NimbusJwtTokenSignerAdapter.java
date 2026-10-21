package com.erp.auth.infrastructure.security.jwt;

import com.erp.auth.domain.model.TokenIdentity;
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
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@Component
public class NimbusJwtTokenSignerAdapter implements TokenSignerPort {

    private final RsaKeyPairManager keyPairManager;
    private final String issuer;
    private final String audience;
    private final Duration accessTokenDuration;
    private final Duration refreshTokenDuration;
    private final Duration passwordResetTokenDuration;

    public NimbusJwtTokenSignerAdapter(
            RsaKeyPairManager keyPairManager,
            @Value("${erp.security.jwt.issuer:https://auth.erp-automotriz.com}") String issuer,
            @Value("${erp.security.jwt.audience:erp-api-gateway}") String audience,
            @Value("${erp.security.jwt.access-token-expiration-minutes:15}") long accessTokenExpirationMinutes,
            @Value("${erp.security.jwt.refresh-token-expiration-days:7}") long refreshTokenExpirationDays,
            @Value("${erp.security.jwt.password-reset-token-expiration-minutes:30}") long passwordResetTokenExpirationMinutes) {
        this.keyPairManager = keyPairManager;
        this.issuer = issuer;
        this.audience = audience;
        this.accessTokenDuration = Duration.ofMinutes(accessTokenExpirationMinutes);
        this.refreshTokenDuration = Duration.ofDays(refreshTokenExpirationDays);
        this.passwordResetTokenDuration = Duration.ofMinutes(passwordResetTokenExpirationMinutes);
    }

    @Override
    public String generateAccessToken(User user) {
        Instant now = Instant.now();

        List<String> roleNames = user.getRoles().stream()
                .map(r -> r.getCode().name())
                .collect(Collectors.toList());

        JWTClaimsSet.Builder claims = baseClaims(now, now.plus(accessTokenDuration))
                .subject(user.getId().toString())
                .claim("tenant_id", user.getTenantId().getValue().toString())
                .claim("email", user.getEmail().getValue())
                .claim("name", user.getFullName())
                .claim("roles", roleNames);

        return sign(claims.build());
    }

    @Override
    public String generateRefreshToken(User user) {
        Instant now = Instant.now();

        List<String> roleNames = user.getRoles().stream()
                .map(r -> r.getCode().name())
                .collect(Collectors.toList());

        JWTClaimsSet.Builder claims = baseClaims(now, now.plus(refreshTokenDuration))
                .subject(user.getId().toString())
                .claim("tenant_id", user.getTenantId().getValue().toString())
                .claim("roles", roleNames);

        return sign(claims.build());
    }

    @Override
    public String generatePasswordResetToken(UUID userId) {
        Instant now = Instant.now();

        // Sin sujeto: el token viaja por correo y no debe revelar a quien
        // corresponde. Quien lo presenta se localiza por su hash, que es lo
        // que lleva a la fila de la base de datos.
        JWTClaimsSet.Builder claims = baseClaims(now, now.plus(passwordResetTokenDuration))
                .claim("purpose", "PASSWORD_RESET");

        return sign(claims.build());
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
    public String extractTokenId(String token) {
        try {
            return SignedJWT.parse(token).getJWTClaimsSet().getJWTID();
        } catch (Exception e) {
            throw new IllegalStateException("No se pudo extraer el identificador unico del token", e);
        }
    }

    @Override
    public TokenIdentity extractIdentity(String token) {
        try {
            JWTClaimsSet claims = SignedJWT.parse(token).getJWTClaimsSet();
            Date expiration = claims.getExpirationTime();
            return new TokenIdentity(
                    UUID.fromString(claims.getJWTID()),
                    UUID.fromString(claims.getSubject()),
                    expiration != null ? expiration.toInstant() : Instant.now());
        } catch (Exception e) {
            throw new IllegalStateException("No se pudo extraer la identidad del token", e);
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

    @Override
    public String getAudience() {
        return audience;
    }

    /**
     * Claims comunes a los tres tipos de token: emisor, **audiencia**,
     * **identificador unico** ({@code jti}), tiempo de emision y tiempo de
     * expiracion.
     *
     * <p>El identificador unico se genera en cada emision: es lo que permite
     * revocar un token concreto, en lugar de revocar "todos los tokens de
     * este usuario".
     */
    private JWTClaimsSet.Builder baseClaims(Instant issuedAt, Instant expiresAt) {
        return new JWTClaimsSet.Builder()
                .issuer(issuer)
                .audience(audience)
                .jwtID(UUID.randomUUID().toString())
                .issueTime(Date.from(issuedAt))
                .expirationTime(Date.from(expiresAt));
    }

    private String sign(JWTClaimsSet claims) {
        try {
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .keyID(keyPairManager.getKeyId())
                    .build();

            SignedJWT signedJWT = new SignedJWT(header, claims);
            RSASSASigner signer = new RSASSASigner(keyPairManager.getPrivateKey());
            signedJWT.sign(signer);

            return signedJWT.serialize();
        } catch (Exception e) {
            throw new IllegalStateException("Error al generar y firmar el token JWT", e);
        }
    }
}
