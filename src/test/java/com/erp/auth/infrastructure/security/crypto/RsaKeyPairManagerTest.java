package com.erp.auth.infrastructure.security.crypto;

import com.erp.auth.support.TestKeyMaterial;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * El material de firma persiste y su identificador se deriva del material.
 *
 * <p>Una clave efimera hace que cada reinicio invalide todos los tokens
 * emitidos, lo que rompe el escalado horizontal: con varias replicas, cada
 * una firma con una clave distinta y ninguna acepta los tokens de las demas.
 *
 * <p>Ver docs/doc-estado-implementacion.md, hallazgos P0 5.6 y P1 6.1.
 */
class RsaKeyPairManagerTest {

    @Test
    @DisplayName("Sin material de firma, el arranque falla con un mensaje que lo identifica")
    void sinMaterialElArranqueFallaDeFormaExplicita() {
        IllegalStateException excepcion = assertThrows(IllegalStateException.class,
                () -> new RsaKeyPairManager("", "", "", ""));

        assertTrue(excepcion.getMessage().contains("erp.security.jwt.private-key-pem"),
                "El mensaje debe indicar la propiedad que falta: " + excepcion.getMessage());
        assertTrue(excepcion.getMessage().contains("no genera claves en memoria"),
                "El mensaje debe explicar el motivo: " + excepcion.getMessage());
    }

    @Test
    @DisplayName("El identificador es estable para el mismo material")
    void elIdentificadorEsEstableParaElMismoMaterial() {
        RsaKeyPairManager primero = new RsaKeyPairManager(
                TestKeyMaterial.privateKeyPem(), TestKeyMaterial.publicKeyPem(), "", "");
        RsaKeyPairManager segundo = new RsaKeyPairManager(
                TestKeyMaterial.privateKeyPem(), TestKeyMaterial.publicKeyPem(), "", "");

        assertEquals(primero.getKeyId(), segundo.getKeyId(),
                "El mismo material debe producir siempre el mismo identificador");
    }

    @Test
    @DisplayName("Dos materiales distintos producen identificadores distintos")
    void dosMaterialesDistintosProducenIdentificadoresDistintos() {
        RsaKeyPairManager primero = new RsaKeyPairManager(
                TestKeyMaterial.privateKeyPem(), TestKeyMaterial.publicKeyPem(), "", "");

        KeyPair otro = RsaKeyPairManager.Generator.generate();
        RsaKeyPairManager segundo = new RsaKeyPairManager(
                RsaKeyPairManager.Generator.toPem("PRIVATE KEY", otro.getPrivate().getEncoded()),
                RsaKeyPairManager.Generator.toPem("PUBLIC KEY", otro.getPublic().getEncoded()),
                "", "");

        assertNotEquals(primero.getKeyId(), segundo.getKeyId(),
                "Dos materiales distintos no pueden compartir identificador");
    }

    @Test
    @DisplayName("El identificador se deriva del modulo publico")
    void elIdentificadorSeDerivaDelModuloPublico() {
        RsaKeyPairManager manager = new RsaKeyPairManager(
                TestKeyMaterial.privateKeyPem(), TestKeyMaterial.publicKeyPem(), "", "");

        String esperado = RsaKeyPairManager.deriveKeyId((RSAPublicKey) manager.getPublicKey());

        assertEquals(esperado, manager.getKeyId());
    }

    @Test
    @DisplayName("La clave publica y la privada han de corresponder")
    void laClavePublicaYLaPrivadaHanDeCorresponder() {
        KeyPair otro = RsaKeyPairManager.Generator.generate();

        IllegalStateException excepcion = assertThrows(IllegalStateException.class,
                () -> new RsaKeyPairManager(
                        RsaKeyPairManager.Generator.toPem("PRIVATE KEY", otro.getPrivate().getEncoded()),
                        TestKeyMaterial.publicKeyPem(),
                        "", ""));

        assertTrue(excepcion.getMessage().contains("no corresponden"),
                "El mensaje debe indicar que el par no corresponde: " + excepcion.getMessage());
    }

    @Test
    @DisplayName("Con dos claves cargadas, el conjunto publicado contiene las dos")
    void conDosClavesCargadasSePublicanLasDos() {
        KeyPair anterior = RsaKeyPairManager.Generator.generate();

        RsaKeyPairManager manager = new RsaKeyPairManager(
                TestKeyMaterial.privateKeyPem(),
                TestKeyMaterial.publicKeyPem(),
                RsaKeyPairManager.Generator.toPem("PRIVATE KEY", anterior.getPrivate().getEncoded()),
                RsaKeyPairManager.Generator.toPem("PUBLIC KEY", anterior.getPublic().getEncoded()));

        Map<String, Object> jwks = manager.getJwksPublicKeySet();
        @SuppressWarnings("unchecked")
        java.util.List<Map<String, Object>> claves = (java.util.List<Map<String, Object>>) jwks.get("keys");

        assertEquals(2, claves.size(), "El conjunto de claves debe contener las dos claves");
        assertNotEquals(claves.get(0).get("kid"), claves.get(1).get("kid"),
                "Las dos claves deben tener identificadores distintos");
        assertEquals(manager.getKeyId(), claves.get(0).get("kid"),
                "La clave vigente es la primera del conjunto");
    }

    @Test
    @DisplayName("La herramienta de linea de comandos produce un par que el servicio carga")
    void laHerramientaProduceUnParQueElServicioCarga() {
        KeyPair generado = RsaKeyPairManager.Generator.generate();

        RsaKeyPairManager manager = new RsaKeyPairManager(
                RsaKeyPairManager.Generator.toPem("PRIVATE KEY", generado.getPrivate().getEncoded()),
                RsaKeyPairManager.Generator.toPem("PUBLIC KEY", generado.getPublic().getEncoded()),
                "", "");

        RSAKey jwk = manager.getRsaJwk();
        assertNotNull(jwk);
        assertEquals(RsaKeyPairManager.deriveKeyId((RSAPublicKey) generado.getPublic()), manager.getKeyId(),
                "El identificador derivado debe coincidir con el que el servicio calcula");
    }

    @Test
    @DisplayName("La clave anterior a medias se rechaza con un mensaje explicito")
    void laClaveAnteriorAMediasSeRechaza() {
        KeyPair anterior = RsaKeyPairManager.Generator.generate();

        IllegalStateException excepcion = assertThrows(IllegalStateException.class,
                () -> new RsaKeyPairManager(
                        TestKeyMaterial.privateKeyPem(),
                        TestKeyMaterial.publicKeyPem(),
                        RsaKeyPairManager.Generator.toPem("PRIVATE KEY", anterior.getPrivate().getEncoded()),
                        ""));

        assertTrue(excepcion.getMessage().contains("a medias"),
                "El mensaje debe indicar que falta la mitad del material: " + excepcion.getMessage());
    }
}
