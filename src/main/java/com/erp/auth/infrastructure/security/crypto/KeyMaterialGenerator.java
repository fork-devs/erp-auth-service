package com.erp.auth.infrastructure.security.crypto;

import java.security.KeyPair;

/**
 * Command-line utility to generate persistent RSA key material for JWT signing.
 *
 * <p>Key material is generated **once** and stored in the deployment secrets manager.
 * The service reads the keys at startup rather than generating ephemeral keys in-memory.
 *
 * <p>Usage:
 *
 * <pre>
 *   ./mvnw -q compile exec:java \
 *       -Dexec.mainClass=com.erp.auth.infrastructure.security.crypto.KeyMaterialGenerator
 * </pre>
 *
 * <p>Output format is ready to paste into environment variables or secret vaults:
 *
 * <pre>
 *   JWT_PRIVATE_KEY_PEM="""..."""
 *   JWT_PUBLIC_KEY_PEM="""..."""
 * </pre>
 *
 * <p>The key identifier ({@code kid}) is derived directly from the key material modulo hash,
 * preventing key-id desynchronization.
 */
public final class KeyMaterialGenerator {

    private KeyMaterialGenerator() {
    }

    public static void main(String[] args) {
        KeyPair keyPair = RsaKeyPairManager.Generator.generate();
        System.out.println(RsaKeyPairManager.Generator.describe(keyPair));
    }
}
