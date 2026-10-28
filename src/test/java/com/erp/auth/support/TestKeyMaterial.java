package com.erp.auth.support;

import com.erp.auth.infrastructure.security.crypto.RsaKeyPairManager;

import java.security.KeyPair;

/**
 * Signing key material for tests.
 *
 * <p>The authentication service does not generate in-memory keys on the fly:
 * it reads configured key material and fails to boot if missing. Tests start
 * the Spring context, so they require valid key material.
 *
 * <p>Key material is generated once per test suite execution and shared across
 * tests, ensuring tokens issued in one test can be verified in another.
 */
public final class TestKeyMaterial {

    private static final String PRIVATE_KEY_PEM;
    private static final String PUBLIC_KEY_PEM;

    static {
        KeyPair keyPair = RsaKeyPairManager.Generator.generate();
        PRIVATE_KEY_PEM = RsaKeyPairManager.Generator.toPem("PRIVATE KEY", keyPair.getPrivate().getEncoded());
        PUBLIC_KEY_PEM = RsaKeyPairManager.Generator.toPem("PUBLIC KEY", keyPair.getPublic().getEncoded());
    }

    private TestKeyMaterial() {
    }

    public static String privateKeyPem() {
        return PRIVATE_KEY_PEM;
    }

    public static String publicKeyPem() {
        return PUBLIC_KEY_PEM;
    }
}
