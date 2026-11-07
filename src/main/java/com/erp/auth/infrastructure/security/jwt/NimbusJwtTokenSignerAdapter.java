package com.erp.auth.infrastructure.security.jwt;

import com.erp.auth.domain.model.TokenIdentity;
import com.erp.auth.domain.model.User;
import com.erp.auth.domain.port.TokenSignerPort;
import com.erp.auth.domain.valueobject.UserId;
import com.erp.auth.infrastructure.security.crypto.RsaKeyPairManager;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Collectors;

@Component
public class NimbusJwtTokenSignerAdapter implements TokenSignerPort {

    private static final String DEFAULT_PEPPER = "default-dev-token-hash-pepper-change-in-production-32chars";

    private final RsaKeyPairManager keyPairManager;
    private final String issuer;
    private final String audience;
    private final Duration accessTokenDuration;
    private final Duration refreshTokenDuration;
    private final Duration passwordResetTokenDuration;
    private final String hashPepper;
    private final Clock clock;

    public NimbusJwtTokenSignerAdapter(
            RsaKeyPairManager keyPairManager,
            @Value("${erp.security.jwt.issuer:https://auth.erp-automotriz.com}") String issuer,
            @Value("${erp.security.jwt.audience:erp-api-gateway}") String audience,
            @Value("${erp.security.jwt.access-token-expiration-minutes:15}") long accessTokenExpirationMinutes,
            @Value("${erp.security.jwt.refresh-token-expiration-days:7}") long refreshTokenExpirationDays,
            @Value("${erp.security.jwt.password-reset-token-expiration-minutes:30}") long passwordResetTokenExpirationMinutes) {
        this(keyPairManager, issuer, audience, accessTokenExpirationMinutes, refreshTokenExpirationDays, passwordResetTokenExpirationMinutes, DEFAULT_PEPPER, Clock.systemUTC());
    }

    public NimbusJwtTokenSignerAdapter(
            RsaKeyPairManager keyPairManager,
            String issuer,
            String audience,
            long accessTokenExpirationMinutes,
            long refreshTokenExpirationDays,
            long passwordResetTokenExpirationMinutes,
            Clock clock) {
        this(keyPairManager, issuer, audience, accessTokenExpirationMinutes, refreshTokenExpirationDays, passwordResetTokenExpirationMinutes, DEFAULT_PEPPER, clock);
    }

    @Autowired
    public NimbusJwtTokenSignerAdapter(
            RsaKeyPairManager keyPairManager,
            @Value("${erp.security.jwt.issuer:https://auth.erp-automotriz.com}") String issuer,
            @Value("${erp.security.jwt.audience:erp-api-gateway}") String audience,
            @Value("${erp.security.jwt.access-token-expiration-minutes:15}") long accessTokenExpirationMinutes,
            @Value("${erp.security.jwt.refresh-token-expiration-days:7}") long refreshTokenExpirationDays,
            @Value("${erp.security.jwt.password-reset-token-expiration-minutes:30}") long passwordResetTokenExpirationMinutes,
            @Value("${erp.security.token.hash-pepper:" + DEFAULT_PEPPER + "}") String hashPepper,
            @Autowired(required = false) Clock clock) {
        if (accessTokenExpirationMinutes <= 0 || refreshTokenExpirationDays <= 0 || passwordResetTokenExpirationMinutes <= 0) {
            throw new IllegalArgumentException("Token expiration durations must be strictly positive");
        }
        this.keyPairManager = Objects.requireNonNull(keyPairManager, "keyPairManager cannot be null");
        this.issuer = Objects.requireNonNull(issuer, "issuer cannot be null");
        this.audience = Objects.requireNonNull(audience, "audience cannot be null");
        this.accessTokenDuration = Duration.ofMinutes(accessTokenExpirationMinutes);
        this.refreshTokenDuration = Duration.ofDays(refreshTokenExpirationDays);
        this.passwordResetTokenDuration = Duration.ofMinutes(passwordResetTokenExpirationMinutes);
        this.hashPepper = (hashPepper != null && !hashPepper.isBlank()) ? hashPepper : DEFAULT_PEPPER;
        this.clock = clock != null ? clock : Clock.systemUTC();
    }

    @Override
    public String generateAccessToken(User user) {
        Instant now = clock.instant();

        List<String> roleNames = user.getRoles().stream()
                .map(r -> r.getCode().name())
                .collect(Collectors.toList());

        JWTClaimsSet.Builder claims = baseClaims(now, now.plus(accessTokenDuration))
                .subject(user.getId().toString())
                .claim("tenant_id", user.getTenantId().getValue().toString())
                .claim("roles", roleNames)
                .claim("type", "access");

        return sign(claims.build());
    }

    @Override
    public String generateRefreshToken(User user) {
        Instant now = clock.instant();

        JWTClaimsSet.Builder claims = baseClaims(now, now.plus(refreshTokenDuration))
                .subject(user.getId().toString())
                .claim("tenant_id", user.getTenantId().getValue().toString())
                .claim("type", "refresh");

        return sign(claims.build());
    }

    @Override
    public String generatePasswordResetToken(UserId userId) {
        return generatePasswordResetToken(userId.getValue());
    }

    @Override
    public String generatePasswordResetToken(UUID userId) {
        Instant now = clock.instant();

        JWTClaimsSet.Builder claims = baseClaims(now, now.plus(passwordResetTokenDuration))
                .subject(userId != null ? userId.toString() : null)
                .claim("type", "password_reset")
                .claim("purpose", "PASSWORD_RESET");

        return sign(claims.build());
    }

    @Override
    public String hashToken(String rawToken) {
        if (rawToken == null) {
            throw new IllegalArgumentException("Raw token cannot be null");
        }
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKey = new SecretKeySpec(hashPepper.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(secretKey);
            byte[] hmacBytes = mac.doFinal(rawToken.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hmacBytes);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException("Algoritmo HMAC-SHA256 no disponible o clave invalida", e);
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
            if (expiration == null) {
                throw new IllegalStateException("El token no contiene fecha de expiracion");
            }
            if (claims.getJWTID() == null || claims.getSubject() == null) {
                throw new IllegalStateException("El token carece de jti o sub");
            }
            String tenantIdStr = (String) claims.getClaim("tenant_id");
            com.erp.auth.domain.valueobject.TenantId tenantId = tenantIdStr != null
                    ? new com.erp.auth.domain.valueobject.TenantId(UUID.fromString(tenantIdStr))
                    : null;
            return new TokenIdentity(
                    UUID.fromString(claims.getJWTID()),
                    UUID.fromString(claims.getSubject()),
                    tenantId,
                    expiration.toInstant());
        } catch (Exception e) {
            throw new IllegalStateException("No se pudo extraer la identidad del token: " + e.getMessage(), e);
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
            throw new IllegalStateException("Fallo al firmar el token JWT", e);
        }
    }
}
