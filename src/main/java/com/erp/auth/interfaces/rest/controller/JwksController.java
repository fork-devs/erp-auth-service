package com.erp.auth.interfaces.rest.controller;

import com.erp.auth.domain.port.TokenSignerPort;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@Tag(name = "JWKS", description = "Endpoint público para distribución de claves criptográficas públicas")
public class JwksController {

    private final TokenSignerPort tokenSignerPort;
    private final String issuer;

    public JwksController(TokenSignerPort tokenSignerPort) {
        this(tokenSignerPort, "https://auth.erp-automotriz.com");
    }

    @Autowired
    public JwksController(TokenSignerPort tokenSignerPort,
                          @Value("${erp.auth.jwt.issuer:https://auth.erp-automotriz.com}") String issuer) {
        this.tokenSignerPort = tokenSignerPort;
        this.issuer = issuer;
    }

    @GetMapping(value = "/.well-known/jwks.json", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Obtener JSON Web Key Set (JWKS)", description = "Retorna el conjunto de claves públicas RSA para validación de tokens JWT en el API Gateway")
    public ResponseEntity<Map<String, Object>> getJwks() {
        return ResponseEntity.ok(tokenSignerPort.getJwksPublicKeySet());
    }

    @GetMapping(value = "/.well-known/openid-configuration", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Obtener documento de configuración OpenID Connect (OIDC Discovery)",
               description = "Retorna la metadata del proveedor de identidad para autodescubrimiento en Kong Gateway")
    public ResponseEntity<Map<String, Object>> getOpenIdConfiguration() {
        return ResponseEntity.ok(Map.of(
                "issuer", issuer,
                "jwks_uri", issuer + "/.well-known/jwks.json",
                "id_token_signing_alg_values_supported", List.of("RS256"),
                "response_types_supported", List.of("token"),
                "subject_types_supported", List.of("public")
        ));
    }
}
