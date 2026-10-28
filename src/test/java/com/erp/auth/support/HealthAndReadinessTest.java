package com.erp.auth.support;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The service exposes health and readiness probes, detailing the status
 * of verified components.
 *
 * <p>Without these endpoints, an orchestrator cannot determine whether the
 * service is responding or if its database is reachable to route traffic properly.
 */
@SpringBootTest
@AutoConfigureMockMvc
class HealthAndReadinessTest extends AbstractPostgresIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("La comprobacion de salud informa del estado de la base de datos")
    void laSaludInformaDelEstadoDeLaBaseDeDatos() throws Exception {
        mockMvc.perform(get("/actuator/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"))
                .andExpect(jsonPath("$.components").exists());
        System.out.println("DEBUG salud: " + mockMvc.perform(get("/actuator/health"))
                .andReturn().getResponse().getContentAsString());
    }

    @Test
    @DisplayName("La comprobacion de disponibilidad informa de si la base esta accesible")
    void laDisponibilidadInformaDeSiLaBaseEstaAccesible() throws Exception {
        mockMvc.perform(get("/actuator/health/readiness"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"))
                .andExpect(jsonPath("$.components.database.status").value("UP"));
    }

    @Test
    @DisplayName("La comprobacion de vivencia responde")
    void laVivenciaResponde() throws Exception {
        mockMvc.perform(get("/actuator/health/liveness"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"));
    }
}
