package com.erp.auth.interfaces.rest.controller;

import com.erp.auth.application.usecase.AuthenticateUserUseCase;
import com.erp.auth.application.usecase.PasswordResetUseCase;
import com.erp.auth.application.usecase.RefreshTokenUseCase;
import com.erp.auth.application.usecase.RevokeAccessTokenUseCase;
import com.erp.auth.application.usecase.RevokeTokenUseCase;
import com.erp.auth.infrastructure.config.I18nConfig;
import com.erp.auth.interfaces.rest.advice.GlobalRestExceptionHandler;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.MessageSource;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
class I18nValidationTest {

    private MockMvc mockMvc;

    @Mock
    private AuthenticateUserUseCase authenticateUserUseCase;
    @Mock
    private RefreshTokenUseCase refreshTokenUseCase;
    @Mock
    private RevokeAccessTokenUseCase revokeAccessTokenUseCase;
    @Mock
    private RevokeTokenUseCase revokeTokenUseCase;
    @Mock
    private PasswordResetUseCase passwordResetUseCase;

    @BeforeEach
    void setUp() {
        I18nConfig config = new I18nConfig();
        MessageSource messageSource = config.messageSource();
        LocalValidatorFactoryBean validator = config.getValidator(messageSource);
        validator.afterPropertiesSet();

        AuthController controller = new AuthController(
                authenticateUserUseCase,
                refreshTokenUseCase,
                revokeAccessTokenUseCase,
                revokeTokenUseCase,
                passwordResetUseCase
        );

        mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setValidator(validator)
                .setLocaleResolver(config.localeResolver())
                .setControllerAdvice(new GlobalRestExceptionHandler(messageSource))
                .build();
    }

    @Test
    @DisplayName("Accept-Language: es debe retornar mensajes de validación en español")
    void shouldReturnValidationErrorsInSpanish() throws Exception {
        mockMvc.perform(post("/api/v1/auth/refresh")
                        .header("Accept-Language", "es")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.title").value("Solicitud Inválida"))
                .andExpect(jsonPath("$.errorCode").value("VALIDATION_ERROR"))
                .andExpect(jsonPath("$.invalidParams['refreshToken']").value("El token de actualización es obligatorio."))
                .andExpect(jsonPath("$.invalidParams['tenantId']").value("El identificador de taller es obligatorio."));
    }

    @Test
    @DisplayName("Accept-Language: en debe retornar mensajes de validación en inglés")
    void shouldReturnValidationErrorsInEnglish() throws Exception {
        mockMvc.perform(post("/api/v1/auth/refresh")
                        .header("Accept-Language", "en")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.title").value("Validation Error"))
                .andExpect(jsonPath("$.errorCode").value("VALIDATION_ERROR"))
                .andExpect(jsonPath("$.invalidParams['refreshToken']").value("Refresh token is required."))
                .andExpect(jsonPath("$.invalidParams['tenantId']").value("Tenant identifier is required."));
    }

    @Test
    @DisplayName("Sin header Accept-Language debe usar locale por defecto (es)")
    void shouldFallbackToDefaultLocaleWhenHeaderMissing() throws Exception {
        mockMvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.title").value("Solicitud Inválida"))
                .andExpect(jsonPath("$.errorCode").value("VALIDATION_ERROR"))
                .andExpect(jsonPath("$.invalidParams['refreshToken']").value("El token de actualización es obligatorio."));
    }

    @Test
    @DisplayName("IllegalArgumentException debe retornar ProblemDetail con errorCode INVALID_ARGUMENT")
    void shouldHandleIllegalArgumentExceptionWithCanonicalErrorCode() throws Exception {
        when(refreshTokenUseCase.refreshToken(any()))
                .thenThrow(new IllegalArgumentException("Custom invalid argument"));

        mockMvc.perform(post("/api/v1/auth/refresh")
                        .header("Accept-Language", "en")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"dummy-token\",\"tenantId\":\"1fdde303-e5db-4710-88aa-f4caca55ac53\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.title").value("Invalid Argument"))
                .andExpect(jsonPath("$.errorCode").value("INVALID_ARGUMENT"))
                .andExpect(jsonPath("$.type").value("https://errors.erp-automotriz.com/auth/invalid-argument"));
    }

    @Test
    @DisplayName("Exception no controlada debe retornar ProblemDetail con errorCode INTERNAL_SERVER_ERROR")
    void shouldHandleGeneralExceptionWithCanonicalErrorCode() throws Exception {
        when(authenticateUserUseCase.authenticate(any()))
                .thenThrow(new RuntimeException("Simulated unexpected failure"));

        mockMvc.perform(post("/api/v1/auth/login")
                        .header("Accept-Language", "es")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"user@example.com\",\"password\":\"validPassword123\",\"tenantId\":\"1fdde303-e5db-4710-88aa-f4caca55ac53\"}"))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.title").value("Error Interno"))
                .andExpect(jsonPath("$.errorCode").value("INTERNAL_SERVER_ERROR"))
                .andExpect(jsonPath("$.type").value("https://errors.erp-automotriz.com/auth/internal-error"));
    }
}
