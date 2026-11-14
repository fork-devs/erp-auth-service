package com.erp.auth.infrastructure.security.jwt;

import com.erp.auth.domain.model.Role;
import com.erp.auth.domain.model.RoleCode;
import com.erp.auth.domain.model.User;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.domain.valueobject.PasswordHash;
import com.erp.auth.domain.valueobject.TenantId;
import com.erp.auth.infrastructure.security.crypto.RsaKeyPairManager;
import com.erp.auth.support.TestKeyMaterial;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Contract test for JWT claims structure, type validation, and zero-PII enforcement.
 */
class TokenClaimsContractTest {

    private static final String ISSUER = "https://auth.test.erp-automotriz.com";
    private static final String AUDIENCE = "erp-api-gateway";

    private NimbusJwtTokenSignerAdapter signer;
    private User usuario;

    @BeforeEach
    void setUp() {
        RsaKeyPairManager manager = new RsaKeyPairManager(
                TestKeyMaterial.privateKeyPem(), TestKeyMaterial.publicKeyPem(), "", "");
        signer = new NimbusJwtTokenSignerAdapter(manager, ISSUER, AUDIENCE, 15, 7, 30);

        usuario = User.create(
                new TenantId(UUID.fromString("aaaaaaaa-1111-1111-1111-111111111111")),
                Email.of("contrato@taller.pe"),
                PasswordHash.of("$2a$12$hash"),
                "Usuario de Contrato",
                Set.of(
                        new Role(UUID.randomUUID(), RoleCode.WORKSHOP_ADMIN, "Administrador"),
                        new Role(UUID.randomUUID(), RoleCode.SERVICE_ADVISOR, "Asesor"),
                        new Role(UUID.randomUUID(), RoleCode.TECHNICIAN, "Mecanico")));
    }

    @Test
    @DisplayName("El token de acceso lleva roles como array, claim type: access, y no contiene PII (email, fullName)")
    void elTokenDeAccesoLlevaLosRolesYTypeAccessSinPII() throws Exception {
        SignedJWT token = SignedJWT.parse(signer.generateAccessToken(usuario));

        Object roles = token.getJWTClaimsSet().getClaim("roles");
        assertTrue(roles instanceof List, "El claim de roles debe ser un array");
        assertEquals(3, ((List<?>) roles).size());
        assertTrue(((List<?>) roles).contains("WORKSHOP_ADMIN"));

        assertEquals("access", token.getJWTClaimsSet().getStringClaim("type"));
        assertNull(token.getJWTClaimsSet().getClaim("email"), "El access token no debe filtrar email (PII)");
        assertNull(token.getJWTClaimsSet().getClaim("name"), "El access token no debe filtrar nombre completo (PII)");
    }

    @Test
    @DisplayName("El token lleva el claim de audiencia")
    void elTokenLlevaElClaimDeAudiencia() throws Exception {
        SignedJWT token = SignedJWT.parse(signer.generateAccessToken(usuario));

        List<String> audiences = token.getJWTClaimsSet().getAudience();

        assertNotNull(audiences);
        assertTrue(audiences.contains(AUDIENCE));
    }

    @Test
    @DisplayName("Cada emision produce un identificador unico, y viaja en el token")
    void cadaEmisionProduceUnIdentificadorUnico() throws Exception {
        String primero = signer.generateAccessToken(usuario);
        String segundo = signer.generateAccessToken(usuario);

        String idPrimero = SignedJWT.parse(primero).getJWTClaimsSet().getJWTID();
        String idSegundo = SignedJWT.parse(segundo).getJWTClaimsSet().getJWTID();

        assertNotNull(idPrimero);
        assertNotNull(idSegundo);
        assertNotEquals(idPrimero, idSegundo);
        assertEquals(idPrimero, signer.extractTokenId(primero));
    }

    @Test
    @DisplayName("El token de refresco lleva claim type: refresh y NO lleva roles (evitar stale privileges)")
    void elTokenDeRefrescoNoLlevaRolesYLlevaTypeRefresh() throws Exception {
        SignedJWT token = SignedJWT.parse(signer.generateRefreshToken(usuario));

        assertEquals(ISSUER, token.getJWTClaimsSet().getIssuer());
        assertTrue(token.getJWTClaimsSet().getAudience().contains(AUDIENCE));
        assertNotNull(token.getJWTClaimsSet().getJWTID());
        assertNotNull(token.getJWTClaimsSet().getExpirationTime());
        assertNotNull(token.getJWTClaimsSet().getIssueTime());
        assertEquals(usuario.getId().toString(), token.getJWTClaimsSet().getSubject());
        assertEquals("refresh", token.getJWTClaimsSet().getStringClaim("type"));
        assertNull(token.getJWTClaimsSet().getClaim("roles"), "El refresh token nunca debe portar roles");
    }

    @Test
    @DisplayName("El token de restablecimiento vincula el userId y lleva type: password_reset")
    void elTokenDeRestablecimientoVinculaUserIdYLlevaType() throws Exception {
        SignedJWT token = SignedJWT.parse(signer.generatePasswordResetToken(usuario.getId()));

        assertEquals(ISSUER, token.getJWTClaimsSet().getIssuer());
        assertTrue(token.getJWTClaimsSet().getAudience().contains(AUDIENCE));
        assertNotNull(token.getJWTClaimsSet().getJWTID());
        assertEquals(usuario.getId().toString(), token.getJWTClaimsSet().getSubject());
        assertEquals("password_reset", token.getJWTClaimsSet().getStringClaim("type"));
    }
}
