package com.erp.auth.support;

import com.erp.auth.application.service.AccessTokenRevocationService;
import com.erp.auth.domain.model.Role;
import com.erp.auth.domain.model.RoleCode;
import com.erp.auth.domain.model.TokenIdentity;
import com.erp.auth.domain.model.User;
import com.erp.auth.domain.port.RevokedTokenRepositoryPort;
import com.erp.auth.domain.port.TokenSignerPort;
import com.erp.auth.domain.port.UnitOfWork;
import com.erp.auth.domain.port.RoleRepositoryPort;
import com.erp.auth.domain.port.UserRepositoryPort;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.domain.valueobject.PasswordHash;
import com.erp.auth.domain.valueobject.TenantId;
import com.erp.auth.infrastructure.security.RevokedTokenCleanupTask;
import com.erp.auth.infrastructure.security.filter.JwtAuthenticationFilter;
import com.erp.auth.infrastructure.security.crypto.RsaKeyPairManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * La revocacion de un token de acceso es efectiva.
 *
 * <p>Sin ella, cerrar la sesion solo revocaba el token de refresco: el token
 * de acceso seguia siendo una credencial valida hasta que expiraba, con lo
 * que un token robado servia para lo que quedaba de su ventana.
 *
 * <p>Ver docs/doc-estado-implementacion.md, hallazgo P1 6.20.
 */
class AccessTokenRevocationTest extends AbstractPostgresIntegrationTest {

    private static final UUID TALLER = UUID.fromString("dddd1111-2222-3333-4444-555555555555");
    private static final String EMISOR = "https://auth.test.erp-automotriz.com";
    private static final String AUDIENCIA = "erp-api-gateway";

    @Autowired
    private RevokedTokenRepositoryPort revokedTokenRepositoryPort;

    @Autowired
    private AccessTokenRevocationService accessTokenRevocationService;

    @Autowired
    private RevokedTokenCleanupTask revokedTokenCleanupTask;

    @Autowired
    private TokenSignerPort tokenSignerPort;

    @Autowired
    private UserRepositoryPort userRepositoryPort;

    @Autowired
    private RoleRepositoryPort roleRepositoryPort;

    @Autowired
    private UnitOfWork unitOfWork;

    @Autowired
    private RsaKeyPairManager keyPairManager;

    private User usuario;

    @BeforeEach
    void setUp() {
        Role admin = roleRepositoryPort.findByCode(RoleCode.ADMIN_TALLER)
                .orElseThrow(() -> new AssertionError("El rol ADMIN_TALLER deberia estar sembrado"));
        usuario = User.create(
                new TenantId(TALLER),
                Email.of("revocacion-" + UUID.randomUUID() + "@taller.pe"),
                PasswordHash.of("$2a$12$hash"),
                "Usuario",
                Set.of(admin));

        try (com.erp.auth.infrastructure.persistence.rls.TenantContextScope scope =
                     com.erp.auth.infrastructure.persistence.rls.TenantContextScope.forTenant(TALLER)) {
            unitOfWork.runInTransaction(() -> userRepositoryPort.save(usuario));
        }
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("La migracion crea la tabla con su indice por fecha de expiracion")
    void laMigracionCreaLaTablaConSuIndice() throws Exception {
        try (var connection = EmbeddedPostgresSupport.openOwnerConnection();
             var statement = connection.createStatement();
             var rs = statement.executeQuery(
                     "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                     + "WHERE n.nspname = 'public' AND c.relname = 'idx_revoked_tokens_expires_at'")) {
            rs.next();
            assertEquals(1, rs.getInt(1), "Debe existir el indice por expires_at");
        }
    }

    @Test
    @DisplayName("Un token registrado como revocado se encuentra, y uno que no, no")
    void unTokenRevocadoSeEncuentraYUnoQueNoNo() {
        UUID revocado = UUID.randomUUID();
        UUID noRevocado = UUID.randomUUID();

        unitOfWork.runInTransaction(() -> revokedTokenRepositoryPort.revoke(
                revocado, usuario.getId(), Instant.now().plusSeconds(900)));

        assertTrue(revokedTokenRepositoryPort.isRevoked(revocado),
                "El token registrado como revocado debe encontrarse");
        assertFalse(revokedTokenRepositoryPort.isRevoked(noRevocado),
                "Un token que no se ha revocado no debe aparecer");
    }

    @Test
    @DisplayName("Un token revocado es rechazado por el propio servicio de autenticacion")
    void unTokenRevocadoEsRechazado() throws Exception {
        String token = tokenSignerPort.generateAccessToken(usuario);
        TokenIdentity identity = tokenSignerPort.extractIdentity(token);

        // Antes de revocar, el token se acepta.
        filtrar(token);
        assertNotNull(SecurityContextHolder.getContext().getAuthentication(),
                "El token debe aceptarse mientras no se revoque");

        unitOfWork.runInTransaction(() -> revokedTokenRepositoryPort.revoke(
                identity.tokenId(), usuario.getId(), identity.expiresAt()));

        SecurityContextHolder.clearContext();
        MockHttpServletResponse response = filtrar(token);

        assertEquals(401, response.getStatus(),
                "Un token revocado debe rechazarse aunque no haya expirado");
        assertNull(SecurityContextHolder.getContext().getAuthentication(),
                "Un token revocado no puede autenticar la peticion");
    }

    @Test
    @DisplayName("Tras el cierre de sesion, el token de acceso del usuario es rechazado")
    void trasElCierreDeSesionElTokenEsRechazado() throws Exception {
        String token = tokenSignerPort.generateAccessToken(usuario);
        TokenIdentity identity = tokenSignerPort.extractIdentity(token);

        accessTokenRevocationService.revokeAccessToken(token);

        assertTrue(revokedTokenRepositoryPort.isRevoked(identity.tokenId()),
                "El cierre de sesion debe dejar el token de acceso revocado");

        SecurityContextHolder.clearContext();
        MockHttpServletResponse response = filtrar(token);

        assertEquals(401, response.getStatus(),
                "Tras el cierre de sesion, el token de acceso debe rechazarse");
    }

    @Test
    @DisplayName("La limpieza elimina las revocaciones de tokens ya expirados")
    void laLimpiezaEliminaLasRevocacionesVencidas() {
        UUID vencido = UUID.randomUUID();
        UUID vigente = UUID.randomUUID();

        unitOfWork.runInTransaction(() -> {
            revokedTokenRepositoryPort.revoke(vencido, usuario.getId(), Instant.now().minusSeconds(60));
            revokedTokenRepositoryPort.revoke(vigente, usuario.getId(), Instant.now().plusSeconds(900));
        });

        revokedTokenCleanupTask.eliminarRevocacionesVencidas();

        assertFalse(revokedTokenRepositoryPort.isRevoked(vencido),
                "La revocacion de un token ya expirado debe eliminarse");
        assertTrue(revokedTokenRepositoryPort.isRevoked(vigente),
                "La revocacion de un token que aun no expira debe conservarse");
    }

    private MockHttpServletResponse filtrar(String token) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/users");
        request.addHeader("Authorization", "Bearer " + token);
        MockHttpServletResponse response = new MockHttpServletResponse();

        JwtAuthenticationFilter filter = new JwtAuthenticationFilter(
                keyPairManager, revokedTokenRepositoryPort, EMISOR, AUDIENCIA);
        filter.doFilter(request, response, (req, res) -> {
        });

        return response;
    }
}
