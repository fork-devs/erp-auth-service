package com.erp.auth.interfaces.rest.controller;

import com.erp.auth.application.dto.command.GoogleLoginCommand;
import com.erp.auth.application.dto.command.LoginCommand;
import com.erp.auth.application.dto.command.RefreshTokenCommand;
import com.erp.auth.application.dto.command.SendOtpCommand;
import com.erp.auth.application.dto.command.VerifyOtpCommand;
import com.erp.auth.application.dto.result.AuthResult;
import com.erp.auth.application.usecase.AuthenticateUserUseCase;
import com.erp.auth.application.usecase.GoogleLoginUseCase;
import com.erp.auth.application.usecase.PasswordResetUseCase;
import com.erp.auth.application.usecase.RefreshTokenUseCase;
import com.erp.auth.application.usecase.RevokeAccessTokenUseCase;
import com.erp.auth.application.usecase.RevokeTokenUseCase;
import com.erp.auth.application.usecase.SendOtpUseCase;
import com.erp.auth.application.usecase.VerifyOtpUseCase;
import com.erp.auth.interfaces.rest.advice.GlobalRestExceptionHandler;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
class AuthenticationControllerTest {

    @Mock
    private AuthenticateUserUseCase authenticateUserUseCase;
    @Mock
    private GoogleLoginUseCase googleLoginUseCase;
    @Mock
    private RefreshTokenUseCase refreshTokenUseCase;
    @Mock
    private RevokeAccessTokenUseCase revokeAccessTokenUseCase;
    @Mock
    private RevokeTokenUseCase revokeTokenUseCase;
    @Mock
    private PasswordResetUseCase passwordResetUseCase;
    @Mock
    private SendOtpUseCase sendOtpUseCase;
    @Mock
    private VerifyOtpUseCase verifyOtpUseCase;

    private MockMvc mockMvc;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setUp() {
        AuthenticationController controller = new AuthenticationController(
                authenticateUserUseCase,
                googleLoginUseCase,
                refreshTokenUseCase,
                revokeAccessTokenUseCase,
                revokeTokenUseCase,
                passwordResetUseCase,
                sendOtpUseCase,
                verifyOtpUseCase
        );
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new GlobalRestExceptionHandler())
                .build();
    }

    @Test
    @DisplayName("POST /api/v1/authentication/sessions returns 200 and tokens")
    void testCreateSession() throws Exception {
        UUID userId = UUID.randomUUID();
        UUID tenantId = UUID.randomUUID();
        AuthResult authResult = new AuthResult(
                "access-token", "jti-1", "refresh-token", "Bearer",
                900, userId, tenantId, "user@example.com", "User", Set.of("CUSTOMER")
        );
        when(authenticateUserUseCase.authenticate(any(LoginCommand.class))).thenReturn(authResult);

        mockMvc.perform(post("/api/v1/authentication/sessions")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "email", "user@example.com",
                                "password", "Password123!",
                                "tenantId", tenantId.toString()
                        ))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("access-token"))
                .andExpect(jsonPath("$.refreshToken").value("refresh-token"));
    }

    @Test
    @DisplayName("POST /api/v1/authentication/sessions/google returns 200 and tokens")
    void testGoogleLogin() throws Exception {
        UUID userId = UUID.randomUUID();
        UUID tenantId = UUID.randomUUID();
        AuthResult authResult = new AuthResult(
                "access-token", "jti-1", "refresh-token", "Bearer",
                900, userId, tenantId, "google@example.com", "Google User", Set.of("CUSTOMER")
        );
        when(googleLoginUseCase.loginWithGoogle(any(GoogleLoginCommand.class))).thenReturn(authResult);

        mockMvc.perform(post("/api/v1/authentication/sessions/google")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "idToken", "mock-google-id-token"
                        ))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("access-token"))
                .andExpect(jsonPath("$.email").value("google@example.com"));
    }

    @Test
    @DisplayName("POST /api/v1/authentication/sessions/refresh returns 200 and rotated tokens")
    void testRefreshSession() throws Exception {
        UUID userId = UUID.randomUUID();
        UUID tenantId = UUID.randomUUID();
        AuthResult authResult = new AuthResult(
                "new-access-token", "jti-2", "new-refresh-token", "Bearer",
                900, userId, tenantId, "user@example.com", "User", Set.of("CUSTOMER")
        );
        when(refreshTokenUseCase.refreshToken(any(RefreshTokenCommand.class))).thenReturn(authResult);

        mockMvc.perform(post("/api/v1/authentication/sessions/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "refreshToken", "refresh-token-uuid",
                                "tenantId", tenantId.toString()
                        ))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("new-access-token"))
                .andExpect(jsonPath("$.refreshToken").value("new-refresh-token"));
    }

    @Test
    @DisplayName("DELETE /api/v1/authentication/sessions revokes tokens and returns 204")
    void testLogoutSession() throws Exception {
        UUID tenantId = UUID.randomUUID();

        mockMvc.perform(delete("/api/v1/authentication/sessions")
                        .header("Authorization", "Bearer access-token-jwt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "refreshToken", "refresh-token-uuid",
                                "tenantId", tenantId.toString()
                        ))))
                .andExpect(status().isNoContent());

        verify(revokeTokenUseCase).revokeToken("refresh-token-uuid");
        verify(revokeAccessTokenUseCase).revokeAccessToken("access-token-jwt");
    }

    @Test
    @DisplayName("POST /api/v1/authentication/password-recoveries returns 200")
    void testPasswordRecovery() throws Exception {
        UUID tenantId = UUID.randomUUID();

        mockMvc.perform(post("/api/v1/authentication/password-recoveries")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "email", "user@example.com",
                                "tenantId", tenantId.toString()
                        ))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").exists());
    }

    @Test
    @DisplayName("POST /api/v1/authentication/password-resets returns 200")
    void testPasswordReset() throws Exception {
        UUID tenantId = UUID.randomUUID();

        mockMvc.perform(post("/api/v1/authentication/password-resets")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "token", "token-reset-123",
                                "newPassword", "NewPassword123!",
                                "tenantId", tenantId.toString()
                        ))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Password updated successfully"));
    }

    @Test
    @DisplayName("POST /api/v1/authentication/otp/send returns 200")
    void testSendOtp() throws Exception {
        mockMvc.perform(post("/api/v1/authentication/otp/send")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "email", "user@example.com"
                        ))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Código OTP enviado exitosamente"));

        verify(sendOtpUseCase).sendOtp(any(SendOtpCommand.class));
    }

    @Test
    @DisplayName("POST /api/v1/authentication/otp/verify returns 200")
    void testVerifyOtp() throws Exception {
        mockMvc.perform(post("/api/v1/authentication/otp/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "email", "user@example.com",
                                "code", "123456"
                        ))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Código OTP verificado exitosamente"));

        verify(verifyOtpUseCase).verifyOtp(any(VerifyOtpCommand.class));
    }
}
