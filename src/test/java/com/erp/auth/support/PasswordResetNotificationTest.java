package com.erp.auth.support;

import com.erp.auth.application.service.AuthenticateUserService;
import com.erp.auth.application.service.PasswordResetService;
import com.erp.auth.application.service.RefreshTokenService;
import com.erp.auth.application.usecase.PasswordResetUseCase;
import com.erp.auth.domain.model.NotificationMessage;
import com.erp.auth.domain.model.Role;
import com.erp.auth.domain.model.RoleCode;
import com.erp.auth.domain.model.User;
import com.erp.auth.domain.port.NotificationPort;
import com.erp.auth.domain.port.RefreshTokenRepositoryPort;
import com.erp.auth.domain.port.TokenSignerPort;
import com.erp.auth.domain.port.UnitOfWork;
import com.erp.auth.domain.port.UserRepositoryPort;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.domain.valueobject.PasswordHash;
import com.erp.auth.domain.valueobject.TenantId;
import com.erp.auth.interfaces.rest.controller.AuthController;
import com.erp.auth.interfaces.rest.dto.request.ForgotPasswordRequest;
import com.erp.auth.interfaces.rest.dto.request.LoginRequest;
import com.erp.auth.interfaces.rest.dto.request.RefreshTokenRequest;
import com.erp.auth.interfaces.rest.dto.request.ResetPasswordRequest;
import com.erp.auth.infrastructure.persistence.rls.TenantContextScope;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * El token de restablecimiento de contrasena llega a su destinatario, y no
 * a quien lo pide.
 *
 * <p>El caso de uso devolvia el token y el controlador lo descartaba: el
 * token se generaba y se perdia. El flujo era, por tanto, inutilizable, y
 * la unica forma de hacer que funcionara era devolverlo en la respuesta,
 * con lo que cualquiera podria restablecer la contrasena de cualquier
 * cuenta.
 *
 * <p>Ver docs/doc-estado-implementacion.md, hallazgo P1 6.21.
 */
class PasswordResetNotificationTest extends AbstractPostgresIntegrationTest {

    private static final UUID TALLER = UUID.fromString("eeee1111-2222-3333-4444-555555555555");

    @Autowired
    private PasswordResetService passwordResetService;

    @Autowired
    private TokenSignerPort tokenSignerPort;

    @Autowired
    private UserRepositoryPort userRepositoryPort;

    /** Notificaciones entregadas durante el test. */
    private List<NotificationMessage> entregadas;

    @Autowired
    private com.erp.auth.domain.port.RoleRepositoryPort roleRepositoryPort;

    @Autowired
    private UnitOfWork unitOfWork;

    @Autowired
    private com.erp.auth.domain.port.PasswordResetTokenRepositoryPort passwordResetTokenRepositoryPort;

    @Autowired
    private com.erp.auth.domain.port.RefreshTokenRepositoryPort refreshTokenRepositoryPort;

    @Autowired
    private com.erp.auth.domain.port.PasswordEncoderPort passwordEncoderPort;

    @Autowired
    private AuthenticateUserService authenticateUserService;

    @Autowired
    private RefreshTokenService refreshTokenService;

    @BeforeEach
    void setUp() {
        entregadas = new ArrayList<>();
    }

    @Test
    @DisplayName("La respuesta es la misma exista o no la cuenta, y el token no aparece en ella")
    void laRespuestaEsLaMismaYElTokenNoAparece() throws Exception {
        String correo = "restablecimiento-" + UUID.randomUUID() + "@taller.pe";
        crearUsuario(correo);

        MockMvc mockMvc = mockMvc();

        String respuestaExistente = mockMvc.perform(post("/api/v1/auth/forgot-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(cuerpo(correo)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        int entregadasParaCuentaExistente = entregadas.size();

        String respuestaInexistente = mockMvc.perform(post("/api/v1/auth/forgot-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(cuerpo("inexistente-" + UUID.randomUUID() + "@taller.pe")))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        assertEquals(respuestaExistente, respuestaInexistente,
                "La respuesta debe ser identica exista o no la cuenta: si difiere, permite enumerar usuarios");
        assertFalse(respuestaExistente.contains("eyJ"),
                "La respuesta no debe contener el token de restablecimiento");
        assertEquals(1, entregadasParaCuentaExistente,
                "Para una cuenta existente debe entregarse una notificacion");
        assertEquals(1, entregadas.size(),
                "Para una cuenta inexistente no debe entregarse ninguna notificacion");
    }

    @Test
    @DisplayName("La notificacion lleva el token y el destinatario")
    void laNotificacionLlevaElTokenYElDestinatario() throws Exception {
        String correo = "notificacion-" + UUID.randomUUID() + "@taller.pe";
        crearUsuario(correo);

        mockMvc().perform(post("/api/v1/auth/forgot-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(cuerpo(correo)))
                .andExpect(status().isOk());

        assertEquals(1, entregadas.size());
        NotificationMessage notificacion = entregadas.get(0);
        assertEquals(correo, notificacion.recipient(), "La notificacion debe ir al titular de la cuenta");
        assertTrue(notificacion.body().contains("."),
                "El cuerpo de la notificacion debe llevar el token de restablecimiento");
    }

    private void crearUsuario(String correo) {
        Role admin = roleRepositoryPort.findByCode(RoleCode.ADMIN_TALLER)
                .orElseThrow(() -> new AssertionError("El rol ADMIN_TALLER deberia estar sembrado"));
        User user = User.create(
                new TenantId(TALLER),
                Email.of(correo),
                PasswordHash.of(passwordEncoderPort.encode("ContrasenaLarga1!")),
                "Usuario",
                Set.of(admin));

        try (TenantContextScope scope = TenantContextScope.forTenant(TALLER)) {
            unitOfWork.runInTransaction(() -> userRepositoryPort.save(user));
        }
    }

    private String cuerpo(String correo) {
        return """
                {
                  "email": "%s",
                  "tenantId": "%s"
                }
                """.formatted(correo, TALLER);
    }

    /**
     * Controlador con un puerto de notificacion que registra lo entregado.
     */
    private MockMvc mockMvc() {
        NotificationPort registro = entregadas::add;

        PasswordResetUseCase passwordReset = new PasswordResetService(
                userRepositoryPort,
                passwordResetTokenRepositoryPort,
                refreshTokenRepositoryPort,
                passwordEncoderPort,
                tokenSignerPort,
                registro,
                unitOfWork);

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
                passwordReset);

        return MockMvcBuilders.standaloneSetup(controller).build();
    }
}
