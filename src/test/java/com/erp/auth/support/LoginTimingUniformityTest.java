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
import com.erp.auth.interfaces.rest.controller.AuthController;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * El tiempo de respuesta del login no distingue los casos, y el codigo de
 * error tampoco.
 *
 * <p>Sin una verificacion de contrasena en la ruta de cuenta inexistente, el
 * tiempo de respuesta delata si la cuenta existe: la busqueda de una cuenta
 * inexistente es inmediata, y la de una existente cuesta el tiempo del hash.
 * Y si la cuenta bloqueada respondiera con otro codigo, delataria tambien el
 * estado de la cuenta.
 *
 * <p>Ver docs/doc-estado-implementacion.md, hallazgo P1 6.24.
 */
class LoginTimingUniformityTest extends AbstractPostgresIntegrationTest {

    private static final UUID TALLER = UUID.fromString("dddd2222-3333-4444-5555-666677778888");
    private static final String CONTRASENA = "ContrasenaLarga1!";

    /**
     * Margen admite: el caso mas rapido no puede ser menos de la mitad del
     * mas lento. Es generoso, porque el coste del hash varia entre
     * ejecuciones, pero descarta el caso extremo: una cuenta inexistente que
     * responde en una fraccion del tiempo del resto.
     */
    private static final double MARGEN_ADMISIBLE = 0.5;

    @Autowired
    private com.erp.auth.application.service.AuthenticateUserService authenticateUserService;

    @Autowired
    private com.erp.auth.application.service.RefreshTokenService refreshTokenService;

    @Autowired
    private com.erp.auth.application.service.PasswordResetService passwordResetService;

    @Autowired
    private UserRepositoryPort userRepositoryPort;

    @Autowired
    private RoleRepositoryPort roleRepositoryPort;

    @Autowired
    private UnitOfWork unitOfWork;

    @Autowired
    private PasswordEncoderPort passwordEncoderPort;

    private MockMvc mockMvc;
    private String correo;

    @BeforeEach
    void setUp() {
        correo = "cronometro-" + UUID.randomUUID() + "@taller.pe";

        Role asesor = roleRepositoryPort.findByCode(RoleCode.ASESOR)
                .orElseThrow(() -> new AssertionError("El rol ASESOR deberia estar sembrado"));
        User user = User.create(
                new TenantId(TALLER),
                Email.of(correo),
                PasswordHash.of(passwordEncoderPort.encode(CONTRASENA)),
                "Usuario",
                Set.of(asesor));

        try (TenantContextScope scope = TenantContextScope.forTenant(TALLER)) {
            unitOfWork.runInTransaction(() -> userRepositoryPort.save(user));
        }

        AuthController controller = new AuthController(
                authenticateUserService,
                refreshTokenService,
                token -> {
                },
                new com.erp.auth.application.usecase.RevokeTokenUseCase() {
                    @Override
                    public void revokeToken(String refreshToken) {
                    }

                    @Override
                    public void revokeAllUserTokens(UUID userId) {
                    }
                },
                passwordResetService);

        this.mockMvc = MockMvcBuilders.standaloneSetup(controller)
                // El manejador global es parte de la respuesta: es donde se
                // traduce la excepcion al codigo HTTP que ve el cliente.
                .setControllerAdvice(new com.erp.auth.interfaces.rest.advice.GlobalRestExceptionHandler())
                .build();
    }

    @Test
    @DisplayName("Los tres casos tardan lo mismo y responden con el mismo codigo")
    void losTresCasosTardanLoMismoYRespondenConElMismoCodigo() throws Exception {
        // La cuenta se bloquea de verdad, con cinco intentos fallidos.
        for (int i = 0; i < 5; i++) {
            login(correo, "ContrasenaEquivocada1!");
        }

        Medida inexistente = medir("no-existe-" + UUID.randomUUID() + "@taller.pe", CONTRASENA);
        Medida contrasenaIncorrecta = medir(correo, "ContrasenaEquivocada1!");
        Medida cuentaBloqueada = medir(correo, CONTRASENA);

        long masRapido = Math.min(inexistente.milis(),
                Math.min(contrasenaIncorrecta.milis(), cuentaBloqueada.milis()));
        long masLento = Math.max(inexistente.milis(),
                Math.max(contrasenaIncorrecta.milis(), cuentaBloqueada.milis()));

        assertTrue(masLento > 0, "Las mediciones tienen que ser validas");
        assertTrue((double) masRapido >= (double) masLento * MARGEN_ADMISIBLE,
                "El tiempo de respuesta delata el estado de la cuenta. Medidas (ms): inexistente="
                        + inexistente.milis() + ", contrasena incorrecta=" + contrasenaIncorrecta.milis()
                        + ", cuenta bloqueada=" + cuentaBloqueada.milis());

        // El codigo de error tambien tiene que ser el mismo: si la cuenta
        // bloqueada respondiera con otro codigo, el estado se revelaria
        // aunque el tiempo coincidiera.
        assertEquals(inexistente.codigo(), contrasenaIncorrecta.codigo(),
                "La respuesta no debe distinguir la cuenta inexistente de la contrasena incorrecta");
        assertEquals(inexistente.codigo(), cuentaBloqueada.codigo(),
                "La respuesta no debe distinguir la cuenta bloqueada");
    }

    private Medida medir(String correo, String contrasena) throws Exception {
        long inicio = System.nanoTime();
        int codigo = login(correo, contrasena);
        long milis = (System.nanoTime() - inicio) / 1_000_000;
        return new Medida(milis, codigo);
    }

    private int login(String correo, String contrasena) throws Exception {
        String cuerpo = """
                {
                  "email": "%s",
                  "password": "%s",
                  "tenantId": "%s"
                }
                """.formatted(correo, contrasena, TALLER);

        try (TenantContextScope scope = TenantContextScope.forTenant(TALLER)) {
            return mockMvc.perform(post("/api/v1/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(cuerpo))
                    .andReturn().getResponse().getStatus();
        }
    }

    private record Medida(long milis, int codigo) {
    }
}
