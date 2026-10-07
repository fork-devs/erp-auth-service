package com.erp.auth.interfaces.rest.controller;

import com.erp.auth.domain.port.TokenSignerPort;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@Tag(name = "JWKS", description = "Endpoint público para distribución de claves criptográficas públicas")
public class JwksController {

    private final TokenSignerPort tokenSignerPort;

    public JwksController(TokenSignerPort tokenSignerPort) {
        this.tokenSignerPort = tokenSignerPort;
    }

    @GetMapping(value = "/.well-known/jwks.json", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Obtener JSON Web Key Set (JWKS)", description = "Retorna el conjunto de claves públicas RSA para validación de tokens JWT en el API Gateway")
    public ResponseEntity<Map<String, Object>> getJwks() {
        return ResponseEntity.ok(tokenSignerPort.getJwksPublicKeySet());
    }
}
