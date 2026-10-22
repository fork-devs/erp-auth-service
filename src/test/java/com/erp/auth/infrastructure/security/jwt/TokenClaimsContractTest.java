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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Contrato de los claims del token.
 *
 * <p>El token de acceso lleva el conjunto de roles como array, la audiencia
 * para la que se emite y un identificador unico. El token de refresco lleva
 * el mismo conjunto de claims.
 *
 * <p>Ver docs/doc-estado-implementacion.md, hallazgos P0 5.7 y P1 6.20.
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
                        new Role(UUID.randomUUID(), RoleCode.ADMIN_TALLER, "Administrador"),
                        new Role(UUID.randomUUID(), RoleCode.ASESOR, "Asesor"),
                        new Role(UUID.randomUUID(), RoleCode.MECANICO, "Mecanico")));
    }

    @Test
    @DisplayName("El token de acceso lleva los roles como array")
    void elTokenDeAccesoLlevaLosRolesComoArray() throws Exception {
        SignedJWT token = SignedJWT.parse(signer.generateAccessToken(usuario));

        Object roles = token.getJWTClaimsSet().getClaim("roles");

        assertTrue(roles instanceof List, "El claim de roles debe ser un array, no un valor unico");
        assertEquals(3, ((List<?>) roles).size(), "No se puede perder ningun rol");
        assertTrue(((List<?>) roles).contains("ADMIN_TALLER"));
        assertTrue(((List<?>) roles).contains("ASESOR"));
        assertTrue(((List<?>) roles).contains("MECANICO"));
    }

    @Test
    @DisplayName("El token lleva el claim de audiencia")
    void elTokenLlevaElClaimDeAudiencia() throws Exception {
        SignedJWT token = SignedJWT.parse(signer.generateAccessToken(usuario));

        List<String> audiences = token.getJWTClaimsSet().getAudience();

        assertNotNull(audiences, "El token debe declarar su audiencia");
        assertTrue(audiences.contains(AUDIENCE));
    }

    @Test
    @DisplayName("Cada emision produce un identificador unico, y viaja en el token")
    void cadaEmisionProduceUnIdentificadorUnico() throws Exception {
        String primero = signer.generateAccessToken(usuario);
        String segundo = signer.generateAccessToken(usuario);

        String idPrimero = SignedJWT.parse(primero).getJWTClaimsSet().getJWTID();
        String idSegundo = SignedJWT.parse(segundo).getJWTClaimsSet().getJWTID();

        assertNotNull(idPrimero, "El token debe llevar su identificador unico");
        assertNotNull(idSegundo);
        assertNotEquals(idPrimero, idSegundo, "Cada emision debe producir un identificador distinto");
        assertEquals(idPrimero, signer.extractTokenId(primero));
    }

    @Test
    @DisplayName("El token de refresco lleva el mismo conjunto de claims")
    void elTokenDeRefrescoLlevaElMismoConjuntoDeClaims() throws Exception {
        SignedJWT token = SignedJWT.parse(signer.generateRefreshToken(usuario));

        assertEquals(ISSUER, token.getJWTClaimsSet().getIssuer());
        assertTrue(token.getJWTClaimsSet().getAudience().contains(AUDIENCE));
        assertNotNull(token.getJWTClaimsSet().getJWTID());
        assertNotNull(token.getJWTClaimsSet().getExpirationTime());
        assertNotNull(token.getJWTClaimsSet().getIssueTime());
        assertEquals(usuario.getId().toString(), token.getJWTClaimsSet().getSubject());
        assertFalse(((List<?>) token.getJWTClaimsSet().getClaim("roles")).isEmpty());
    }

    @Test
    @DisplayName("El token de restablecimiento no revela a quien corresponde")
    void elTokenDeRestablecimientoNoRevelaLaIdentidad() throws Exception {
        SignedJWT token = SignedJWT.parse(signer.generatePasswordResetToken(usuario.getId()));

        assertEquals(ISSUER, token.getJWTClaimsSet().getIssuer());
        assertTrue(token.getJWTClaimsSet().getAudience().contains(AUDIENCE));
        assertNotNull(token.getJWTClaimsSet().getJWTID());
        assertEquals(null, token.getJWTClaimsSet().getSubject(),
                "El token de restablecimiento viaja por correo: no debe revelar a que usuario corresponde");
    }
}
