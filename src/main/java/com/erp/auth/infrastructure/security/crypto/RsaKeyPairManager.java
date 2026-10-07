package com.erp.auth.infrastructure.security.crypto;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

@Component
public class RsaKeyPairManager {

    private final String keyId;
    private final RSAKey rsaJwk;

    public RsaKeyPairManager(@Value("${erp.security.jwt.key-id:erp-auth-key-2026-v1}") String keyId) {
        this.keyId = keyId;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

            this.rsaJwk = new RSAKey.Builder(publicKey)
                    .privateKey(privateKey)
                    .keyID(this.keyId)
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(JWSAlgorithm.RS256)
                    .build();
        } catch (Exception e) {
            throw new IllegalStateException("Error al inicializar par de claves RSA para JWT", e);
        }
    }

    public RSAKey getRsaJwk() {
        return rsaJwk;
    }

    public RSAPrivateKey getPrivateKey() {
        try {
            return rsaJwk.toRSAPrivateKey();
        } catch (Exception e) {
            throw new IllegalStateException("Error al obtener la clave privada RSA", e);
        }
    }

    public RSAPublicKey getPublicKey() {
        try {
            return rsaJwk.toRSAPublicKey();
        } catch (Exception e) {
            throw new IllegalStateException("Error al obtener la clave pública RSA", e);
        }
    }

    public String getKeyId() {
        return keyId;
    }

    public Map<String, Object> getJwksPublicKeySet() {
        JWKSet jwkSet = new JWKSet(rsaJwk.toPublicJWK());
        return jwkSet.toJSONObject();
    }
}
