package com.erp.auth.interfaces.rest.controller;

import com.erp.auth.infrastructure.security.crypto.RsaKeyPairManager;
import com.erp.auth.infrastructure.security.jwt.NimbusJwtTokenSignerAdapter;
import com.erp.auth.support.TestKeyMaterial;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class JwksControllerIntegrationTest {

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        // El material de firma persiste: se carga, no se genera.
        mockMvc = MockMvcBuilders.standaloneSetup(
                new JwksController(adaptadorCon(claveVigente(), ""))).build();
    }

    @Test
    @DisplayName("GET /.well-known/jwks.json debe retornar conjunto de claves públicas RSA")
    void shouldReturnJwksKeys() throws Exception {
        mockMvc.perform(get("/.well-known/jwks.json")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys").isArray())
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                .andExpect(jsonPath("$.keys[0].use").value("sig"))
                .andExpect(jsonPath("$.keys[0].alg").value("RS256"))
                .andExpect(jsonPath("$.keys[0].n").exists())
                .andExpect(jsonPath("$.keys[0].e").value("AQAB"));
    }

    @Test
    @DisplayName("El identificador publicado corresponde al material de esa clave")
    void elIdentificadorPublicadoCorrespondeAlMaterial() throws Exception {
        RsaKeyPairManager manager = new RsaKeyPairManager(
                TestKeyMaterial.privateKeyPem(), TestKeyMaterial.publicKeyPem(), "", "");

        String esperado = RsaKeyPairManager.deriveKeyId((RSAPublicKey) manager.getPublicKey());

        mockMvc.perform(get("/.well-known/jwks.json").contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].kid").value(esperado));
    }

    @Test
    @DisplayName("Con dos claves cargadas, se publican las dos con identificadores distintos")
    void conDosClavesSePublicanLasDos() throws Exception {
        KeyPair anterior = RsaKeyPairManager.Generator.generate();

        mockMvc = MockMvcBuilders.standaloneSetup(new JwksController(adaptadorCon(
                RsaKeyPairManager.Generator.toPem("PUBLIC KEY", anterior.getPublic().getEncoded()),
                RsaKeyPairManager.Generator.toPem("PRIVATE KEY", anterior.getPrivate().getEncoded()))))
                .build();

        String respuesta = mockMvc.perform(get("/.well-known/jwks.json")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys.length()").value(2))
                .andReturn().getResponse().getContentAsString();

        String primerKid = valorDe(respuesta, 0);
        String segundoKid = valorDe(respuesta, 1);

        assertNotEquals(primerKid, segundoKid, "Las dos claves deben tener identificadores distintos");
    }

    private static String valorDe(String json, int indice) {
        com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        try {
            com.fasterxml.jackson.databind.JsonNode raiz = mapper.readTree(json);
            return raiz.get("keys").get(indice).get("kid").asText();
        } catch (Exception e) {
            throw new IllegalStateException("No se pudo leer el conjunto de claves", e);
        }
    }

    /**
     * Adaptador con la clave vigente y, opcionalmente, la anterior.
     */
    private NimbusJwtTokenSignerAdapter adaptadorCon(String publicaAnterior, String privadaAnterior) {
        RsaKeyPairManager manager = privadaAnterior.isEmpty()
                ? new RsaKeyPairManager(
                        TestKeyMaterial.privateKeyPem(), TestKeyMaterial.publicKeyPem(), "", "")
                : new RsaKeyPairManager(
                        TestKeyMaterial.privateKeyPem(), TestKeyMaterial.publicKeyPem(),
                        privadaAnterior, publicaAnterior);
        return new NimbusJwtTokenSignerAdapter(
                manager, "https://auth.test.erp-automotriz.com", "erp-api-gateway", 15, 7, 30);
    }

    private String claveVigente() {
        return TestKeyMaterial.publicKeyPem();
    }
}
