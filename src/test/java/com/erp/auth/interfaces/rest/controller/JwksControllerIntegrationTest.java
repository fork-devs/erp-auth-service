package com.erp.auth.interfaces.rest.controller;

import com.erp.auth.infrastructure.security.crypto.RsaKeyPairManager;
import com.erp.auth.infrastructure.security.jwt.NimbusJwtTokenSignerAdapter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class JwksControllerIntegrationTest {

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        RsaKeyPairManager keyPairManager = new RsaKeyPairManager("test-auth-key-2026-v1");
        NimbusJwtTokenSignerAdapter signerAdapter = new NimbusJwtTokenSignerAdapter(
                keyPairManager,
                "https://auth.test.erp-automotriz.com",
                15,
                7,
                30
        );
        JwksController jwksController = new JwksController(signerAdapter);
        this.mockMvc = MockMvcBuilders.standaloneSetup(jwksController).build();
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
}
