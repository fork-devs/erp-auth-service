package com.erp.auth.infrastructure.security.filter;

import com.erp.auth.domain.port.RevokedTokenRepositoryPort;
import com.erp.auth.infrastructure.persistence.rls.TenantContextHolder;
import com.erp.auth.infrastructure.security.crypto.RsaKeyPairManager;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final RsaKeyPairManager keyPairManager;
    private final RevokedTokenRepositoryPort revokedTokenRepositoryPort;
    private final String issuer;
    private final String audience;

    public JwtAuthenticationFilter(
            RsaKeyPairManager keyPairManager,
            RevokedTokenRepositoryPort revokedTokenRepositoryPort,
            @Value("${erp.security.jwt.issuer:https://auth.erp-automotriz.com}") String issuer,
            @Value("${erp.security.jwt.audience:erp-api-gateway}") String audience) {
        this.keyPairManager = keyPairManager;
        this.revokedTokenRepositoryPort = revokedTokenRepositoryPort;
        this.issuer = issuer;
        this.audience = audience;
    }

    /**
     * El emisor y la audiencia se comprueban contra los valores
     * configurados. Un token correctamente firmado pero emitido para otro
     * emisor, o para otra audiencia, se rechaza: la firma demuestra que lo
     * emitio alguien con la clave, no que sea para este servicio.
     */
    private boolean emisorYAudienciaCorrectos(SignedJWT signedJWT) {
        try {
            String tokenIssuer = signedJWT.getJWTClaimsSet().getIssuer();
            if (tokenIssuer == null || !tokenIssuer.equals(issuer)) {
                return false;
            }
            List<String> audiences = signedJWT.getJWTClaimsSet().getAudience();
            return audiences != null && audiences.contains(audience);
        } catch (java.text.ParseException e) {
            return false;
        }
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");
        String tenantHeader = request.getHeader("X-Tenant-ID");

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7).trim();
            try {
                SignedJWT signedJWT = SignedJWT.parse(token);
                RSASSAVerifier verifier = new RSASSAVerifier(keyPairManager.getPublicKey());

                if (signedJWT.verify(verifier)) {
                    Date expirationTime = signedJWT.getJWTClaimsSet().getExpirationTime();
                    if (expirationTime != null && expirationTime.after(new Date())
                            && emisorYAudienciaCorrectos(signedJWT)) {
                        String userId = signedJWT.getJWTClaimsSet().getSubject();
                        String tenantIdClaim = (String) signedJWT.getJWTClaimsSet().getClaim("tenant_id");
                        List<?> rolesList = (List<?>) signedJWT.getJWTClaimsSet().getClaim("roles");

                        // Un token sin roles NO se acepta con un rol por
                        // defecto: se rechaza. Asignar un rol que el token no
                        // declara es concede un privilegio que nadie ha
                        // awarding.
                        if (rolesList == null || rolesList.isEmpty()) {
                            response.sendError(HttpServletResponse.SC_UNAUTHORIZED,
                                    "El token no declara roles");
                            return;
                        }

                        // Un token revocado se rechaza aunque su expiracion no
                        // haya vencido: cerrar la sesion tiene que invalidar
                        // la credencial, no solo el token de refresco.
                        String tokenId = signedJWT.getJWTClaimsSet().getJWTID();
                        if (tokenId != null && revokedTokenRepositoryPort.isRevoked(UUID.fromString(tokenId))) {
                            response.sendError(HttpServletResponse.SC_UNAUTHORIZED,
                                    "El token ha sido revocado");
                            return;
                        }

                        if (tenantIdClaim != null) {
                            try {
                                TenantContextHolder.setTenantId(UUID.fromString(tenantIdClaim));
                            } catch (IllegalArgumentException ignored) {}
                        }

                        // La cabecera X-Tenant-ID es una pista, nunca una
                        // autoridad: si viene, se contrasta con el tenant del
                        // token y la peticion se rechaza cuando no coinciden.
                        // Ver docs/doc-estado-implementacion.md, hallazgo P0 5.2.
                        if (tenantHeader != null && !tenantHeader.trim().isEmpty()) {
                            UUID requestedTenantId;
                            try {
                                requestedTenantId = UUID.fromString(tenantHeader.trim());
                            } catch (IllegalArgumentException e) {
                                response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                                        "X-Tenant-ID debe ser un UUID valido");
                                return;
                            }
                            UUID tokenTenantId = TenantContextHolder.getTenantId();
                            if (tokenTenantId == null || !tokenTenantId.equals(requestedTenantId)) {
                                response.sendError(HttpServletResponse.SC_FORBIDDEN,
                                        "El tenant solicitado no coincide con el del token");
                                return;
                            }
                        }

                        List<SimpleGrantedAuthority> authorities = (rolesList != null)
                                ? rolesList.stream()
                                    .map(r -> new SimpleGrantedAuthority("ROLE_" + r.toString()))
                                    .collect(Collectors.toList())
                                : List.of();

                        UsernamePasswordAuthenticationToken authentication =
                                new UsernamePasswordAuthenticationToken(userId, null, authorities);
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                    }
                }
            } catch (Exception e) {
                // Token inválido o corrupto, se continúa la cadena sin autenticar
            }
        }

        try {
            filterChain.doFilter(request, response);
        } finally {
            TenantContextHolder.clear();
        }
    }
}
