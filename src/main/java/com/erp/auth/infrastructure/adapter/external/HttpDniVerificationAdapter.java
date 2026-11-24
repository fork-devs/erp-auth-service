package com.erp.auth.infrastructure.adapter.external;

import com.erp.auth.domain.port.DniVerificationPort;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * HTTP adapter that verifies an 8-digit DNI through erp-integration-hub (RENIEC/Factiliza).
 */
@Component
public class HttpDniVerificationAdapter implements DniVerificationPort {

    private static final Logger log = LoggerFactory.getLogger(HttpDniVerificationAdapter.class);
    private static final String PLATFORM_TENANT = "00000000-0000-0000-0000-000000000000";

    private final String baseUrl;
    private final String internalServiceKey;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    @Autowired
    public HttpDniVerificationAdapter(
            @Value("${erp.integration-hub.base-url:http://localhost:8085}") String baseUrl,
            @Value("${erp.security.internal-service-key:erp_internal_secret_service_key_2026}") String internalServiceKey) {
        this(baseUrl, internalServiceKey, HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_2)
                .connectTimeout(Duration.ofSeconds(5))
                .build(), new ObjectMapper());
    }

    public HttpDniVerificationAdapter(
            String baseUrl,
            String internalServiceKey,
            HttpClient httpClient,
            ObjectMapper objectMapper) {
        this.baseUrl = (baseUrl != null && !baseUrl.isBlank()) ? baseUrl.trim().replaceAll("/+$", "") : "http://localhost:8085";
        this.internalServiceKey = internalServiceKey != null ? internalServiceKey.trim() : "";
        this.httpClient = httpClient != null ? httpClient : HttpClient.newHttpClient();
        this.objectMapper = objectMapper != null ? objectMapper : new ObjectMapper();
    }

    @Override
    public DniVerificationResult verifyDni(String dni) {
        if (dni == null || !dni.matches("^\\d{8}$")) {
            return DniVerificationResult.invalid(dni);
        }

        try {
            String uriString = baseUrl + "/api/v1/integrations/validate/lookup?type=DNI&number=" + dni;
            HttpRequest.Builder reqBuilder = HttpRequest.newBuilder()
                    .uri(URI.create(uriString))
                    .timeout(Duration.ofSeconds(6))
                    .header("Accept", "application/json")
                    .header("X-Service-Name", "erp-auth-service")
                    .header("X-Tenant-ID", PLATFORM_TENANT)
                    .GET();

            if (!internalServiceKey.isBlank()) {
                reqBuilder.header("X-Internal-Service-Key", internalServiceKey);
            }

            HttpResponse<String> resp = httpClient.send(reqBuilder.build(), HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() == 200 && resp.body() != null && !resp.body().isBlank()) {
                JsonNode root = objectMapper.readTree(resp.body());
                boolean verified = root.has("verified") && root.get("verified").asBoolean();
                if (verified) {
                    String fullName = extractField(root, "fullName", "nombreCompleto");
                    if (fullName == null) {
                        String first = extractField(root, "firstName", "nombres");
                        String p = extractField(root, "firstSurname", "paternalSurname", "apellidoPaterno");
                        String m = extractField(root, "secondSurname", "maternalSurname", "apellidoMaterno");
                        fullName = String.join(" ",
                                java.util.stream.Stream.of(first, p, m)
                                        .filter(s -> s != null && !s.isBlank())
                                        .toList());
                    }
                    return new DniVerificationResult(dni, fullName, true);
                }
            }
            log.info("[IDENTITY ACL] DNI {} not verified in integration hub (status: {})", dni, resp.statusCode());
        } catch (Exception e) {
            log.error("[IDENTITY ACL] Failure querying integration hub for DNI {}: {}", dni, e.getMessage());
        }

        return DniVerificationResult.invalid(dni);
    }

    private String extractField(JsonNode root, String... keys) {
        for (String key : keys) {
            if (root.has(key) && !root.get(key).isNull()) {
                String value = root.get(key).asText();
                if (value != null && !value.isBlank()) {
                    return value.trim();
                }
            }
        }
        return null;
    }
}
