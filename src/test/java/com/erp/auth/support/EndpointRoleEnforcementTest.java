package com.erp.auth.support;

import com.erp.auth.domain.model.Role;
import com.erp.auth.domain.model.RoleCode;
import com.erp.auth.domain.model.User;
import com.erp.auth.domain.port.PasswordEncoderPort;
import com.erp.auth.domain.port.RoleRepositoryPort;
import com.erp.auth.domain.port.UnitOfWork;
import com.erp.auth.domain.port.UserRepositoryPort;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.domain.valueobject.PasswordHash;
import com.erp.auth.domain.valueobject.TenantId;
import com.erp.auth.infrastructure.persistence.rls.TenantContextScope;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.Set;
import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Los endpoints declaran el rol que exigen, y se aplican.
 *
 * <p>Un endpoint sin rol declarado es un endpoint accesible a cualquier
 * principal autenticado, y a veces a cualquiera sin autenticar. La
 * declaracion explicita hace que el contrato sea visible y que un descuido
 * se note.
 *
 * <p>Ver docs/doc-estado-implementacion.md, hallazgo P1 6.19.
 */
@SpringBootTest
class EndpointRoleEnforcementTest extends AbstractPostgresIntegrationTest {

    private static final UUID TALLER = UUID.fromString("11112222-3333-4444-5555-666677778888");

    @Autowired
    private WebApplicationContext context;

    @Autowired
    private UserRepositoryPort userRepositoryPort;

    @Autowired
    private RoleRepositoryPort roleRepositoryPort;

    @Autowired
    private UnitOfWork unitOfWork;

    @Autowired
    private PasswordEncoderPort passwordEncoderPort;

    @Autowired
    private com.erp.auth.domain.port.TokenSignerPort tokenSignerPort;

    private MockMvc mockMvc;
    private String tokenMecanico;
    private String tokenAdmin;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(context)
                .apply(org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers
                        .springSecurity())
                .build();
        // El correo es unico por taller, de modo que cada test necesita el
        // suyo: la base de datos es compartida.
        String sufijo = UUID.randomUUID().toString().substring(0, 8);
        tokenMecanico = crearUsuario("mecanico-" + sufijo + "@taller.pe", RoleCode.MECANICO);
        tokenAdmin = crearUsuario("admin-" + sufijo + "@taller.pe", RoleCode.ADMIN_TALLER);
    }

    @Test
    @DisplayName("El MECANICO recibe 403 al invocar el alta de usuario")
    void elMecanicoRecibe403AlInvocarElAltaDeUsuario() throws Exception {
        mockMvc.perform(post("/api/v1/users")
                        .header("Authorization", "Bearer " + tokenMecanico)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(cuerpoAlta()))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("El ADMIN_TALLER ejecuta el alta de usuario")
    void elAdminTallerEjecutaElAltaDeUsuario() throws Exception {
        mockMvc.perform(post("/api/v1/users")
                        .header("Authorization", "Bearer " + tokenAdmin)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(cuerpoAlta()))
                .andExpect(status().isCreated());
    }

    private String cuerpoAlta() {
        return """
                {
                  "email": "nuevo-%s@taller.pe",
                  "password": "ContrasenaLarga1!",
                  "fullName": "Nuevo Usuario",
                  "role": "MECANICO"
                }
                """.formatted(UUID.randomUUID().toString().substring(0, 8));
    }

    private String crearUsuario(String correo, RoleCode rol) {
        Role rolCatalogo = roleRepositoryPort.findByCode(rol)
                .orElseThrow(() -> new AssertionError("El rol " + rol + " deberia estar sembrado"));
        User user = User.create(
                new TenantId(TALLER),
                Email.of(correo),
                PasswordHash.of(passwordEncoderPort.encode("ContrasenaLarga1!")),
                "Usuario",
                Set.of(rolCatalogo));

        try (TenantContextScope scope = TenantContextScope.forTenant(TALLER)) {
            unitOfWork.runInTransaction(() -> userRepositoryPort.save(user));
        }
        return tokenSignerPort.generateAccessToken(user);
    }
}
