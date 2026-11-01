package com.erp.auth.infrastructure.adapter.notification;

import com.erp.auth.domain.model.NotificationMessage;
import com.erp.auth.domain.port.NotificationPort;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * Production implementation of NotificationPort using Brevo (Sendinblue) Transactional Email API v3.
 */
public class BrevoEmailAdapter implements NotificationPort {

    private static final Logger log = LoggerFactory.getLogger(BrevoEmailAdapter.class);
    private static final String BREVO_SMTP_URL = "https://api.brevo.com/v3/smtp/email";

    private final String apiKey;
    private final String senderEmail;
    private final String senderName;
    private final boolean enabled;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    public BrevoEmailAdapter(String apiKey, String senderEmail, String senderName, boolean enabled) {
        this(apiKey, senderEmail, senderName, enabled, HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_2)
                .connectTimeout(Duration.ofSeconds(6))
                .build(), new ObjectMapper());
    }

    public BrevoEmailAdapter(String apiKey, String senderEmail, String senderName, boolean enabled,
                             HttpClient httpClient, ObjectMapper objectMapper) {
        this.apiKey = apiKey != null ? apiKey.trim() : "";
        this.senderEmail = (senderEmail != null && !senderEmail.isBlank()) ? senderEmail.trim() : "no-reply@driveos.pe";
        this.senderName = (senderName != null && !senderName.isBlank()) ? senderName.trim() : "DriveOS Workshop";
        this.enabled = enabled;
        this.httpClient = httpClient;
        this.objectMapper = objectMapper != null ? objectMapper : new ObjectMapper();
    }

    @Override
    public void deliver(NotificationMessage notification) {
        if (!enabled || apiKey.isBlank()) {
            log.info("[BREVO] Delivery disabled or missing API key. Simulating email dispatch to: {}, subject: {}",
                    notification.recipient(), notification.subject());
            return;
        }

        try {
            log.info("[BREVO] Sending transactional email to: {}, subject: {}",
                    notification.recipient(), notification.subject());

            String htmlBody = buildHtmlContent(notification);

            Map<String, Object> payload = Map.of(
                    "sender", Map.of("name", senderName, "email", senderEmail),
                    "to", List.of(Map.of("email", notification.recipient())),
                    "subject", notification.subject(),
                    "htmlContent", htmlBody,
                    "textContent", notification.body()
            );

            String requestJson = objectMapper.writeValueAsString(payload);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(BREVO_SMTP_URL))
                    .timeout(Duration.ofSeconds(10))
                    .header("api-key", apiKey)
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(requestJson))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() >= 200 && response.statusCode() < 300) {
                log.info("[BREVO] Email sent successfully to: {} (status: {})", notification.recipient(), response.statusCode());
            } else {
                log.error("[BREVO] Failed to send email to {}. Upstream status: {}, response: {}",
                        notification.recipient(), response.statusCode(), response.body());
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("[BREVO] Dispatch thread interrupted for recipient {}: {}", notification.recipient(), e.getMessage());
        } catch (Exception e) {
            log.error("[BREVO] Error during email dispatch to {}: {}", notification.recipient(), e.getMessage());
        }
    }

    private String buildHtmlContent(NotificationMessage notification) {
        return "<!DOCTYPE html>"
                + "<html lang=\"es\">"
                + "<head><meta charset=\"UTF-8\"><title>" + notification.subject() + "</title></head>"
                + "<body style=\"font-family: Arial, sans-serif; background-color: #f4f6f8; padding: 20px;\">"
                + "  <div style=\"max-width: 600px; margin: 0 auto; background-color: #ffffff; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);\">"
                + "    <h2 style=\"color: #1a365d; margin-top: 0;\">DriveOS Workshop</h2>"
                + "    <p style=\"color: #4a5568; font-size: 16px; line-height: 1.5;\">" + notification.body() + "</p>"
                + "    <hr style=\"border: 0; border-top: 1px solid #e2e8f0; margin: 20px 0;\" />"
                + "    <p style=\"color: #a0aec0; font-size: 12px;\">Este es un mensaje automático de seguridad. Por favor, no responda a este correo.</p>"
                + "  </div>"
                + "</body>"
                + "</html>";
    }
}
