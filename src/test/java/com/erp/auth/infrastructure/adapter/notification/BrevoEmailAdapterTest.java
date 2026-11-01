package com.erp.auth.infrastructure.adapter.notification;

import com.erp.auth.domain.model.NotificationMessage;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class BrevoEmailAdapterTest {

    @Mock
    private HttpClient httpClient;

    @Mock
    private HttpResponse<String> httpResponse;

    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
    }

    @Test
    @DisplayName("Should send email successfully via Brevo v3 API when enabled and valid key provided")
    void shouldSendEmailSuccessfully() throws Exception {
        // Given
        String apiKey = "xkeysib-test-123456789";
        String senderEmail = "soporte@driveos.pe";
        String senderName = "DriveOS Workshop";
        BrevoEmailAdapter adapter = new BrevoEmailAdapter(apiKey, senderEmail, senderName, true, httpClient, objectMapper);

        when(httpResponse.statusCode()).thenReturn(201);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(httpResponse);

        NotificationMessage message = NotificationMessage.of("test@user.com", "Código de Verificación", "Su código es: 123456");

        // When
        adapter.deliver(message);

        // Then
        ArgumentCaptor<HttpRequest> requestCaptor = ArgumentCaptor.forClass(HttpRequest.class);
        verify(httpClient).send(requestCaptor.capture(), any(HttpResponse.BodyHandler.class));

        HttpRequest sentRequest = requestCaptor.getValue();
        assertThat(sentRequest.uri().toString()).isEqualTo("https://api.brevo.com/v3/smtp/email");
        assertThat(sentRequest.headers().firstValue("api-key")).contains(apiKey);
        assertThat(sentRequest.headers().firstValue("Content-Type")).contains("application/json");
        assertThat(sentRequest.headers().firstValue("Accept")).contains("application/json");
    }

    @Test
    @DisplayName("Should not call HTTP client when delivery is disabled")
    void shouldNotCallHttpWhenDisabled() throws Exception {
        // Given
        BrevoEmailAdapter adapter = new BrevoEmailAdapter("xkeysib-some-key", "no-reply@driveos.pe", "DriveOS", false, httpClient, objectMapper);
        NotificationMessage message = NotificationMessage.of("test@user.com", "Test Subject", "Test Body");

        // When
        adapter.deliver(message);

        // Then
        verifyNoInteractions(httpClient);
    }

    @Test
    @DisplayName("Should not call HTTP client when API key is blank")
    void shouldNotCallHttpWhenApiKeyIsBlank() throws Exception {
        // Given
        BrevoEmailAdapter adapter = new BrevoEmailAdapter("   ", "no-reply@driveos.pe", "DriveOS", true, httpClient, objectMapper);
        NotificationMessage message = NotificationMessage.of("test@user.com", "Test Subject", "Test Body");

        // When
        adapter.deliver(message);

        // Then
        verifyNoInteractions(httpClient);
    }

    @Test
    @DisplayName("Should handle HTTP error status code gracefully without propagating exception")
    void shouldHandleHttpErrorGracefully() throws Exception {
        // Given
        BrevoEmailAdapter adapter = new BrevoEmailAdapter("xkeysib-invalid-key", "no-reply@driveos.pe", "DriveOS", true, httpClient, objectMapper);

        when(httpResponse.statusCode()).thenReturn(401);
        when(httpResponse.body()).thenReturn("{\"code\":\"unauthorized\",\"message\":\"Key not found\"}");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(httpResponse);

        NotificationMessage message = NotificationMessage.of("test@user.com", "OTP Code", "Your code is 654321");

        // When & Then (should not throw)
        adapter.deliver(message);

        verify(httpClient).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }

    @Test
    @DisplayName("Should handle network exception gracefully")
    void shouldHandleNetworkExceptionGracefully() throws Exception {
        // Given
        BrevoEmailAdapter adapter = new BrevoEmailAdapter("xkeysib-key", "no-reply@driveos.pe", "DriveOS", true, httpClient, objectMapper);

        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(new IOException("Connection timed out"));

        NotificationMessage message = NotificationMessage.of("test@user.com", "OTP Code", "Your code is 654321");

        // When & Then (should not throw)
        adapter.deliver(message);

        verify(httpClient).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }
}
