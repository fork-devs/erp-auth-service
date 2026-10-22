package com.erp.auth.infrastructure.security.filter;

import com.erp.auth.domain.model.Role;
import com.erp.auth.domain.model.RoleCode;
import com.erp.auth.domain.model.User;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.domain.valueobject.PasswordHash;
import com.erp.auth.domain.valueobject.TenantId;
import com.erp.auth.domain.port.RevokedTokenRepositoryPort;
import com.erp.auth.infrastructure.security.crypto.RsaKeyPairManager;
import com.erp.auth.support.TestKeyMaterial;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.mockito.Mockito.mock;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * El filtro de autenticacion exige un token coherente con el servicio.
 *
 * <p>Un token correctamente firmado pero emitido por otro emisor, o para
 * otra audiencia, se rechaza: la firma demuestra que lo emitio alguien con
 * la clave, no que sea para este servicio. Y un token sin roles se rechaza,
 * en lugar de recibir un rol por defecto.
 *
 * <p>Ver docs/doc-estado-implementacion.md, hallazgos P0 5.7 y P1 6.24.
 */
class JwtAuthenticationFilterContractTest {

    private static final String ISSUER = "https://auth.test.erp-automotriz.com";
    private static final String AUDIENCE = "erp-api-gateway";

    private RsaKeyPairManager keyPairManager;
    private JwtAuthenticationFilter filter;

    /** En este test no hay revocaciones: el filtro no encuentra ninguna. */
    private final RevokedTokenRepositoryPort revocado = mock(RevokedTokenRepositoryPort.class);

    @BeforeEach
    void setUp() {
        keyPairManager = new RsaKeyPairManager(
                TestKeyMaterial.privateKeyPem(), TestKeyMaterial.publicKeyPem(), "", "");
        filter = new JwtAuthenticationFilter(keyPairManager, revocado, ISSUER, AUDIENCE);
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("Un token con emisor distinto se rechaza")
    void unTokenConEmisorDistintoSeRechaza() throws Exception {
        String token = firmar("https://otro-emisor.example", AUDIENCE, List.of("ADMIN_TALLER"));

        MockHttpServletResponse response = filtrar(token);

        assertNull(SecurityContextHolder.getContext().getAuthentication(),
                "Un token de otro emisor no puede autenticar la peticion");
        assertNotEquals(HttpServletResponse.SC_CREATED, response.getStatus(),
                "La peticion no debe servirse como si el token fuera valido");
    }

    @Test
    @DisplayName("Un token con audiencia distinta se rechaza")
    void unTokenConAudienciaDistintaSeRechaza() throws Exception {
        String token = firmar(ISSUER, "otro-servicio", List.of("ADMIN_TALLER"));

        MockHttpServletResponse response = filtrar(token);

        assertNull(SecurityContextHolder.getContext().getAuthentication(),
                "Un token emitido para otra audiencia no puede autenticar la peticion");
        assertNotEquals(HttpServletResponse.SC_CREATED, response.getStatus(),
                "La peticion no debe servirse como si el token fuera valido");
    }

    @Test
    @DisplayName("Un token sin claim de roles se rechaza")
    void unTokenSinRolesSeRechaza() throws Exception {
        String token = firmar(ISSUER, AUDIENCE, null);

        MockHttpServletResponse response = filtrar(token);

        assertEquals(HttpServletResponse.SC_UNAUTHORIZED, response.getStatus(),
                "Un token sin roles no puede autenticarse");
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    @DisplayName("Un token coherente se acepta y aporta sus roles")
    void unTokenCoherenteSeAcepta() throws Exception {
        String token = firmar(ISSUER, AUDIENCE, List.of("ADMIN_TALLER", "MECANICO"));

        MockHttpServletResponse response = filtrar(token);

        assertEquals(200, response.getStatus());
        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
        assertEquals(2, SecurityContextHolder.getContext().getAuthentication().getAuthorities().size());
    }

    private MockHttpServletResponse filtrar(String token) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/users");
        request.addHeader("Authorization", "Bearer " + token);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, (req, res) -> {
        });

        return response;
    }

    private String firmar(String issuer, String audience, List<String> roles) throws Exception {
        User usuario = User.create(
                new TenantId(UUID.fromString("aaaaaaaa-1111-1111-1111-111111111111")),
                Email.of("filtro@taller.pe"),
                PasswordHash.of("$2a$12$hash"),
                "Usuario",
                Set.of(new Role(UUID.randomUUID(), RoleCode.ADMIN_TALLER, "Administrador")));

        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .audience(audience)
                .jwtID(UUID.randomUUID().toString())
                .subject(usuario.getId().toString())
                .claim("tenant_id", usuario.getTenantId().getValue().toString())
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + 600_000));

        if (roles != null) {
            claims.claim("roles", roles);
        }

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(keyPairManager.getKeyId())
                .build();

        SignedJWT jwt = new SignedJWT(header, claims.build());
        jwt.sign(new RSASSASigner(keyPairManager.getPrivateKey()));
        return jwt.serialize();
    }
}
