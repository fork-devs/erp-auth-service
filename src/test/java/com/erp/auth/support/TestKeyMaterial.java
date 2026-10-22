package com.erp.auth.support;

import com.erp.auth.infrastructure.security.crypto.RsaKeyPairManager;

import java.security.KeyPair;

/**
 * Material de firma para los tests.
 *
 * <p>El servicio de autenticacion ya **no genera** claves en memoria: las
 * lee de la fuente configurada y falla al arrancar si no estan. Los tests
 * arrancan el contexto de Spring, de modo que necesitan material valido.
 *
 * <p>Se genera una vez por ejecucion de la suite, y es el mismo para todos
 * los tests: asi, un token emitido en un test lo puede validar otro.
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
