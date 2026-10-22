package com.erp.auth.infrastructure.security.filter;

import com.erp.auth.domain.model.Role;
import com.erp.auth.domain.model.RoleCode;
import com.erp.auth.domain.model.User;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.domain.valueobject.PasswordHash;
import com.erp.auth.domain.valueobject.TenantId;
import com.erp.auth.infrastructure.persistence.rls.TenantContextHolder;
import com.erp.auth.infrastructure.security.crypto.RsaKeyPairManager;
import com.erp.auth.infrastructure.security.jwt.NimbusJwtTokenSignerAdapter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * El tenant efectivo se deriva del token verificado, nunca de una cabecera del
 * cliente. Ver docs/doc-estado-implementacion.md, hallazgo P0 5.2.
 */
class JwtAuthenticationFilterTenantSourceTest {

    private static final UUID TENANT_A = UUID.fromString("aaaaaaaa-1111-1111-1111-111111111111");
    private static final UUID TENANT_B = UUID.fromString("bbbbbbbb-2222-2222-2222-222222222222");

    private UUID tenantSeenDuringChain;

    private RsaKeyPairManager keyPairManager;
    private NimbusJwtTokenSignerAdapter signer;
    private JwtAuthenticationFilter filter;

    /**
     * El filtro limpia el contexto al terminar la cadena, de modo que el tenant
     * observado durante la peticion se captura con un FilterChain propio.
     */
    private jakarta.servlet.FilterChain capturingChain() {
        return (request, response) -> tenantSeenDuringChain = TenantContextHolder.getTenantId();
    }

    @BeforeEach
    void setUp() {
        keyPairManager = new RsaKeyPairManager("erp-auth-key-test");
        signer = new NimbusJwtTokenSignerAdapter(keyPairManager, "https://auth.test.erp", 15, 7, 30);
        filter = new JwtAuthenticationFilter(keyPairManager);
        TenantContextHolder.clear();
        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void tearDown() {
        TenantContextHolder.clear();
        SecurityContextHolder.clearContext();
        tenantSeenDuringChain = null;
    }

    @Test
    void sinTokenNoSeEstableceTenantAunqueVengaLaCabecera() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/users");
        request.addHeader("X-Tenant-ID", TENANT_B.toString());
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, capturingChain());

        assertNull(tenantSeenDuringChain,
                "Sin token verificado no debe existir contexto de tenant");
        assertEquals(200, response.getStatus(), "La peticion sigue la cadena sin autenticar");
    }

    @Test
    void conTokenValidoElTenantProcedeDelClaim() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/users");
        request.addHeader("Authorization", "Bearer " + tokenFor(TENANT_A));
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, capturingChain());

        assertEquals(TENANT_A, tenantSeenDuringChain,
                "El tenant debe proceder del claim del token verificado");
        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    void conTokenValidoYCabeceraAjenaSeRechaza() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/users");
        request.addHeader("Authorization", "Bearer " + tokenFor(TENANT_A));
        request.addHeader("X-Tenant-ID", TENANT_B.toString());
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, capturingChain());

        assertEquals(403, response.getStatus(),
                "Una cabecera de tenant ajena al token debe rechazarse");
    }

    @Test
    void conTokenValidoYCabeceraCoincidenteSeAcepta() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/users");
        request.addHeader("Authorization", "Bearer " + tokenFor(TENANT_A));
        request.addHeader("X-Tenant-ID", TENANT_A.toString());
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, capturingChain());

        assertEquals(200, response.getStatus(), "estado=" + response.getStatus() + " err=" + response.getErrorMessage());
        assertEquals(TENANT_A, tenantSeenDuringChain, "tenant durante la cadena=" + tenantSeenDuringChain);
    }

    @Test
    void conTokenInvalidoNoSeEstableceTenantAunqueVengaLaCabecera() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/users");
        request.addHeader("Authorization", "Bearer token.invalido");
        request.addHeader("X-Tenant-ID", TENANT_B.toString());
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, capturingChain());

        assertNull(tenantSeenDuringChain,
                "Un token invalido no debe dejar contexto de tenant");
    }

    private String tokenFor(UUID tenantId) {
        User user = User.create(
                new TenantId(tenantId),
                Email.of("usuario@driveos.pe"),
                PasswordHash.of("hash"),
                "Usuario de Prueba",
                Set.of(new Role(UUID.randomUUID(), RoleCode.ASESOR, "Asesor")));
        return signer.generateAccessToken(user);
    }
}
