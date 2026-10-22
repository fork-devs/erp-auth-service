package com.erp.auth.infrastructure.security.crypto;

import java.security.KeyPair;

/**
 * Herramienta de linea de comandos que emite el material de firma vigente.
 *
 * <p>El material se genera **una sola vez** y se guarda en el almacen de
 * secretos del despliegue. El servicio lo lee al arrancar; no lo genera.
 *
 * <p>Uso:
 *
 * <pre>
 *   ./mvnw -q compile exec:java \
 *       -Dexec.mainClass=com.erp.auth.infrastructure.security.crypto.KeyMaterialGenerator
 * </pre>
 *
 * <p>La salida esta pensada para pegarse en un fichero de variables de
 * entorno o en un gestor de secretos:
 *
 * <pre>
 *   JWT_PRIVATE_KEY_PEM="""..."""
 *   JWT_PUBLIC_KEY_PEM="""..."""
 * </pre>
 *
 * <p>El identificador de la clave ({@code kid}) no se configura: se deriva del
 * material, de modo que no puede quedar desincronizado de la clave que
 * realmente se usa.
 */
public final class KeyMaterialGenerator {

    private KeyMaterialGenerator() {
    }

    public static void main(String[] args) {
        KeyPair keyPair = RsaKeyPairManager.Generator.generate();
        System.out.println(RsaKeyPairManager.Generator.describe(keyPair));
    }
}
