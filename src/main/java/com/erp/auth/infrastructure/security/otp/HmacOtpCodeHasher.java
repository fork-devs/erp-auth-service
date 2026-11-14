package com.erp.auth.infrastructure.security.otp;

import com.erp.auth.domain.port.OtpCodeHasher;
import com.erp.auth.domain.valueobject.OtpCodeHash;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

@Component
public class HmacOtpCodeHasher implements OtpCodeHasher {

    private final byte[] pepperBytes;

    public HmacOtpCodeHasher(@Value("${erp.security.token.hash-pepper:default-dev-token-hash-pepper-change-in-production-32chars}") String pepper) {
        this.pepperBytes = (pepper != null && !pepper.isBlank()
                ? pepper
                : "default-dev-token-hash-pepper-change-in-production-32chars").getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public OtpCodeHash hash(String rawCode) {
        if (rawCode == null || rawCode.trim().isEmpty()) {
            throw new IllegalArgumentException("Raw OTP code cannot be blank");
        }
        try {
            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(new SecretKeySpec(pepperBytes, "HmacSHA256"));
            byte[] hash = hmac.doFinal(rawCode.trim().getBytes(StandardCharsets.UTF_8));
            return new OtpCodeHash(HexFormat.of().formatHex(hash));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException("Failed to calculate HMAC-SHA256 for OTP code", e);
        }
    }
}
