package com.erp.auth.infrastructure.security.crypto;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * Management of cryptographic key material used for signing JWT tokens.
 *
 * <p>Key material is **persistent**: read from the configured environment/secret store
 * at startup rather than generated ephemeral in-memory. Ephemeral keys invalidate tokens
 * on every restart and break horizontal scaling across multiple instances.
 *
 * <p>The key identifier ({@code kid}) is **derived directly from the key material**:
 * computed as the SHA-256 hash of the RSA public key modulus. This prevents {@code kid}
 * and key material desynchronization.
 *
 * <p>Supports graceful key rotation by holding both the active signing key and an optional
 * previous key during transition windows (signing with new, verifying and publishing both).
 *
 * <p>See docs/doc-estado-implementacion.md, findings P0 5.6 and P1 6.1.
 */
@Component
public class RsaKeyPairManager {

    /** Byte length of the public modulus hash used as key identifier. */
    private static final int KEY_ID_BYTES = 16;

    private final RSAKey currentJwk;
    private final List<JWK> publishedJwks;

    public RsaKeyPairManager(
            @Value("${erp.security.jwt.private-key-pem:}") String privateKeyPem,
            @Value("${erp.security.jwt.public-key-pem:}") String publicKeyPem,
            @Value("${erp.security.jwt.previous-private-key-pem:}") String previousPrivateKeyPem,
            @Value("${erp.security.jwt.previous-public-key-pem:}") String previousPublicKeyPem) {

        if (privateKeyPem == null || privateKeyPem.isBlank()) {
            throw new IllegalStateException(
                    "No hay material de firma cargado. Defina erp.security.jwt.private-key-pem con la clave "
                    + "privada vigente (PEM PKCS#8) y erp.security.jwt.public-key-pem con la publica "
                    + "correspondiente (PEM X.509). El servicio no genera claves en memoria: una clave "
                    + "efimera invalida todos los tokens emitidos en cada reinicio.");
        }

        this.currentJwk = load(privateKeyPem, publicKeyPem, "vigente");
        this.publishedJwks = new ArrayList<JWK>();
        this.publishedJwks.add(currentJwk.toPublicJWK());

        boolean hayPrevia = notBlank(previousPrivateKeyPem) || notBlank(previousPublicKeyPem);
        if (hayPrevia) {
            if (!notBlank(previousPrivateKeyPem) || !notBlank(previousPublicKeyPem)) {
                throw new IllegalStateException(
                        "La clave anterior esta a medias: para el solapamiento hay que definir las dos, "
                        + "la privada anterior (erp.security.jwt.previous-private-key-pem) y la publica "
                        + "anterior (erp.security.jwt.previous-public-key-pem).");
            }
            this.publishedJwks.add(load(previousPrivateKeyPem, previousPublicKeyPem, "anterior").toPublicJWK());
        }
    }

    public RSAKey getRsaJwk() {
        return currentJwk;
    }

    public RSAPrivateKey getPrivateKey() {
        try {
            return currentJwk.toRSAPrivateKey();
        } catch (Exception e) {
            throw new IllegalStateException("Error al obtener la clave privada RSA", e);
        }
    }

    public RSAPublicKey getPublicKey() {
        try {
            return currentJwk.toRSAPublicKey();
        } catch (Exception e) {
            throw new IllegalStateException("Error al obtener la clave publica RSA", e);
        }
    }

    /**
     * Key identifier of the active signing key, derived from its public key material.
     *
     * @return key identifier ({@code kid})
     */
    public String getKeyId() {
        return currentJwk.getKeyID();
    }

    /**
     * Set of public JWKs published via JWKS: current active key and, during
     * rotation overlap, the previous key.
     *
     * @return JWK set as JSON object map
     */
    public Map<String, Object> getJwksPublicKeySet() {
        JWKSet jwkSet = new JWKSet(publishedJwks);
        return jwkSet.toJSONObject();
    }

    // ------------------------------------------------------------- internal helpers

    private RSAKey load(String privateKeyPem, String publicKeyPem, String descripcion) {
        try {
            PrivateKey privateKey = readPrivateKey(privateKeyPem);
            PublicKey publicKey = notBlank(publicKeyPem)
                    ? readPublicKey(publicKeyPem)
                    : derivePublicKey(privateKey);

            RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) privateKey;

            if (!rsaPublicKey.getModulus().equals(rsaPrivateKey.getModulus())) {
                throw new IllegalStateException(
                        "La clave publica y la privada de la clave " + descripcion + " no corresponden: "
                        + "el modulo publico no coincide con el de la clave privada.");
            }

            return new RSAKey.Builder(rsaPublicKey)
                    .privateKey(rsaPrivateKey)
                    .keyID(deriveKeyId(rsaPublicKey))
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(JWSAlgorithm.RS256)
                    .build();
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException(
                    "No se pudo cargar el material de la clave " + descripcion + ": " + e.getMessage(), e);
        }
    }

    /**
     * Computes the key identifier derived from the public key material modulus hash.
     *
     * <p>The same key material always generates the same key ID, ensuring consistency
     * without relying on manually maintained configuration strings.
     *
     * @param publicKey RSA public key
     * @return URL-safe Base64-encoded key ID
     */
    public static String deriveKeyId(RSAPublicKey publicKey) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(toUnsignedBytes(publicKey.getModulus()));
            byte[] identificador = new byte[KEY_ID_BYTES];
            System.arraycopy(hash, 0, identificador, 0, KEY_ID_BYTES);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(identificador);
        } catch (Exception e) {
            throw new IllegalStateException("No se pudo derivar el identificador de la clave", e);
        }
    }

    private static byte[] toUnsignedBytes(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            byte[] trimmed = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, trimmed, 0, trimmed.length);
            return trimmed;
        }
        return bytes;
    }

    private static PrivateKey readPrivateKey(String pem) throws Exception {
        byte[] der = decodePem(pem, "PRIVATE KEY");
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
    }

    private static PublicKey readPublicKey(String pem) throws Exception {
        byte[] der = decodePem(pem, "PUBLIC KEY");
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
    }

    /**
     * Derives RSA public key from private CRT key. Allows configuring only the private
     * key in secret management systems.
     *
     * @param privateKey RSA private key
     * @return derived RSA public key
     * @throws Exception if public key parameters cannot be extracted
     */
    private static PublicKey derivePublicKey(PrivateKey privateKey) throws Exception {
        if (!(privateKey instanceof RSAPrivateKey rsaPrivateKey)) {
            throw new IllegalStateException("La clave privada cargada no es una clave RSA.");
        }
        if (!(privateKey instanceof java.security.interfaces.RSAPrivateCrtKey crtKey)) {
            throw new IllegalStateException(
                    "La clave privada cargada no expone el exponente publico: no es una clave RSA CRT.");
        }
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(new java.security.spec.RSAPublicKeySpec(
                crtKey.getModulus(), crtKey.getPublicExponent()));
    }

    private static byte[] decodePem(String pem, String tipo) {
        String limpio = pem.replace("-----BEGIN " + tipo + "-----", "")
                .replace("-----END " + tipo + "-----", "")
                .replaceAll("\\s", "");
        if (limpio.isEmpty()) {
            throw new IllegalStateException("El PEM de tipo " + tipo + " esta vacio.");
        }
        return Base64.getDecoder().decode(limpio);
    }

    private static boolean notBlank(String valor) {
        return valor != null && !valor.isBlank();
    }

    /**
     * Generates an RSA key pair and formats it as expected by application configuration.
     */
    public static final class Generator {

        private Generator() {
        }

        public static KeyPair generate() {
            try {
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                keyPairGenerator.initialize(2048);
                return keyPairGenerator.generateKeyPair();
            } catch (Exception e) {
                throw new IllegalStateException("No se pudo generar el par de claves RSA", e);
            }
        }

        public static String toPem(String tipo, byte[] contenido) {
            String base64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(contenido);
            return "-----BEGIN " + tipo + "-----\n" + base64 + "\n-----END " + tipo + "-----\n";
        }

        public static String describe(KeyPair keyPair) {
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            StringBuilder texto = new StringBuilder();
            texto.append("JWT_PRIVATE_KEY_PEM=\"\"\"\n")
                    .append(toPem("PRIVATE KEY", keyPair.getPrivate().getEncoded()))
                    .append("\"\"\"\n\n")
                    .append("JWT_PUBLIC_KEY_PEM=\"\"\"\n")
                    .append(toPem("PUBLIC KEY", keyPair.getPublic().getEncoded()))
                    .append("\"\"\"\n\n")
                    .append("# Identificador derivado del material: ").append(deriveKeyId(publicKey)).append('\n');
            return texto.toString();
        }
    }
}
