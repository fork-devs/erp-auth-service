package com.erp.auth.support;

import com.erp.auth.interfaces.rest.controller.UserController;
import com.erp.auth.interfaces.rest.dto.request.RegisterUserRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * El enrolamiento del segundo factor no expone el secreto ni los codigos de
 * recuperacion en la respuesta.
 *
 * <p>Son credenciales: la respuesta la ve quien pide el enrolamiento, y con
 * el secreto podría generar codigos validos sin necesidad del telefono del
 * usuario.
 */
class SecondFactorEnrollmentResponseTest {

    @Test
    @DisplayName("La respuesta del enrolamiento no contiene el secreto ni los codigos")
    void laRespuestaNoContieneElSecretoNiLosCodigos() throws Exception {
        UUID usuarioId = UUID.randomUUID();
        java.util.List<String> entregadas = new java.util.ArrayList<>();

        // El caso de uso no devuelve nada: el secreto y los codigos salen por
        // el canal de notificacion.
        UserController controller = new UserController(
                null,
                null,
                null,
                (userId, tenantId) -> entregadas.add("notificacion"),
                (userId, tenantId, code) -> {
                });

        MockMvc mockMvc = MockMvcBuilders.standaloneSetup(controller).build();

        Authentication authentication = new UsernamePasswordAuthenticationToken(
                usuarioId.toString(), null, List.of(new SimpleGrantedAuthority("ROLE_MECANICO")));

        String respuesta;
        try (com.erp.auth.infrastructure.persistence.rls.TenantContextScope scope =
                     com.erp.auth.infrastructure.persistence.rls.TenantContextScope
                             .forTenant(UUID.randomUUID())) {
            respuesta = mockMvc.perform(post("/api/v1/users/me/second-factor")
                            .contentType(MediaType.APPLICATION_JSON)
                            .principal(authentication))
                    .andExpect(status().isOk())
                    .andReturn().getResponse().getContentAsString();
        }

        assertFalse(respuesta.contains("otpauth://"),
                "La respuesta no debe contener el enlace de enrolamiento: " + respuesta);
        // El secreto es una cadena Base32 de 32 caracteres. La respuesta no
        // debe contener ninguna cadena de ese tipo.
        assertFalse(respuesta.matches(".*[A-Z2-7]{16,}.*"),
                "La respuesta no debe contener el secreto: " + respuesta);
        assertFalse(respuesta.matches(".*[0-9A-F]{10}-[0-9A-F]{10}.*"),
                "La respuesta no debe contener codigos de recuperacion: " + respuesta);
    }
}
