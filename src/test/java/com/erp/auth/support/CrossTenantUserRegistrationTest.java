package com.erp.auth.support;

import com.erp.auth.domain.model.Role;
import com.erp.auth.domain.model.RoleCode;
import com.erp.auth.domain.model.User;
import com.erp.auth.domain.port.TokenSignerPort;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.domain.valueobject.PasswordHash;
import com.erp.auth.domain.valueobject.TenantId;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Set;
import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Aislamiento entre talleres en el alta de usuarios: los tres vectores de
 * cruce tienen que resultar en denegacion.
 *
 * <p>El atacante es el actor ADMIN_TALLER del taller A; la victima es el
 * taller B.
 *
 * <p>Ver docs/doc-estado-implementacion.md, hallazgos P0 5.1 y P0 5.2.
 */
@SpringBootTest
@AutoConfigureMockMvc
class CrossTenantUserRegistrationTest extends AbstractPostgresIntegrationTest {

    private static final UUID TALLER_ATACANTE = UUID.fromString("aaaaaaaa-1111-1111-1111-111111111111");
    private static final UUID TALLER_VICTIMA = UUID.fromString("bbbbbbbb-2222-2222-2222-222222222222");

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private TokenSignerPort tokenSignerPort;

    @Autowired
    private com.erp.auth.domain.port.RoleRepositoryPort roleRepositoryPort;

    @Test
    void vectorTenantEnElCuerpoNoCreaUsuariosEnElTallerVictima() throws Exception {
        String token = tokenDe(TALLER_ATACANTE);
        long victimUsersBefore = usuariosEn(TALLER_VICTIMA);

        String cuerpo = """
                {
                  "tenantId": "%s",
                  "email": "nuevo@driveos.pe",
                  "password": "contrasena-larga-1",
                  "fullName": "Nuevo Usuario",
                  "role": "MECANICO"
                }
                """.formatted(TALLER_VICTIMA);

        mockMvc.perform(post("/api/v1/users")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(cuerpo))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.tenantId").value(TALLER_ATACANTE.toString()));

        assert usuarioEn(TALLER_ATACANTE) : "El usuario debe crearse en el taller del atacante";
        assert usuariosEn(TALLER_VICTIMA) == victimUsersBefore
                : "No debe crearse ningun usuario en el taller victima";
    }

    @Test
    void vectorTenantEnLaCabeceraSeRechaza() throws Exception {
        String token = tokenDe(TALLER_ATACANTE);
        long victimUsersBefore = usuariosEn(TALLER_VICTIMA);

        String cuerpo = """
                {
                  "email": "cabecera@driveos.pe",
                  "password": "contrasena-larga-2",
                  "fullName": "Usuario Con Cabecera",
                  "role": "MECANICO"
                }
                """;

        mockMvc.perform(post("/api/v1/users")
                        .header("Authorization", "Bearer " + token)
                        .header("X-Tenant-ID", TALLER_VICTIMA.toString())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(cuerpo))
                .andExpect(status().isForbidden());

        assert usuariosEn(TALLER_VICTIMA) == victimUsersBefore
                : "No debe crearse ningun usuario en el taller victima";
    }

    @Test
    void vectorTenantOmitidoSeRechaza() throws Exception {
        long victimUsersBefore = usuariosEn(TALLER_VICTIMA);
        long attackerUsersBefore = usuariosEn(TALLER_ATACANTE);

        String cuerpo = """
                {
                  "email": "sin-taller@driveos.pe",
                  "password": "contrasena-larga-3",
                  "fullName": "Usuario Sin Taller",
                  "role": "MECANICO"
                }
                """;

        mockMvc.perform(post("/api/v1/users")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(cuerpo))
                .andExpect(status().is4xxClientError());

        assert usuariosEn(TALLER_VICTIMA) == victimUsersBefore;
        assert usuariosEn(TALLER_ATACANTE) == attackerUsersBefore
                : "No debe crearse ningun usuario sin contexto de taller";
    }

    @Test
    void unMecanicoNoPuedeCrearUsuarios() throws Exception {
        Role mecanico = roleRepositoryPort.findByCode(RoleCode.MECANICO)
                .orElseThrow(() -> new AssertionError("El rol MECANICO deberia estar sembrado"));
        User user = User.create(new TenantId(TALLER_ATACANTE),
                Email.of("mecanico@driveos.pe"),
                PasswordHash.of("hash"),
                "Mecanico",
                Set.of(mecanico));
        String token = tokenSignerPort.generateAccessToken(user);

        String cuerpo = """
                {
                  "email": "escalada@driveos.pe",
                  "password": "contrasena-larga-4",
                  "fullName": "Escalada",
                  "role": "SUPERADMIN"
                }
                """;

        mockMvc.perform(post("/api/v1/users")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(cuerpo))
                .andExpect(status().isForbidden());
    }

    private String tokenDe(UUID tenantId) {
        Role admin = roleRepositoryPort.findByCode(RoleCode.ADMIN_TALLER)
                .orElseThrow(() -> new AssertionError("El rol ADMIN_TALLER deberia estar sembrado"));
        User user = User.create(new TenantId(tenantId),
                Email.of("admin@driveos.pe"),
                PasswordHash.of("hash"),
                "Admin Taller",
                Set.of(admin));
        return tokenSignerPort.generateAccessToken(user);
    }

    private long usuariosEn(UUID tenantId) throws Exception {
        try (var connection = EmbeddedPostgresSupport.openOwnerConnection();
             var statement = connection.createStatement();
             var rs = statement.executeQuery("SELECT count(*) FROM users WHERE tenant_id = '" + tenantId + "'")) {
            rs.next();
            return rs.getLong(1);
        }
    }

    private boolean usuarioEn(UUID tenantId) throws Exception {
        return usuariosEn(tenantId) > 0;
    }
}
