package com.erp.auth.interfaces.rest.controller;

import com.erp.auth.application.dto.command.UpdateUserEmailCommand;
import com.erp.auth.application.dto.command.UpdateUserPasswordCommand;
import com.erp.auth.application.dto.result.AuthResult;
import com.erp.auth.application.dto.result.UserResult;
import com.erp.auth.application.usecase.ConfirmSecondFactorEnrollmentUseCase;
import com.erp.auth.application.usecase.EnrollSecondFactorUseCase;
import com.erp.auth.application.usecase.GetUserByIdUseCase;
import com.erp.auth.application.usecase.GetUserProfileUseCase;
import com.erp.auth.application.usecase.ListTenantUsersUseCase;
import com.erp.auth.application.usecase.RegisterUserUseCase;
import com.erp.auth.application.usecase.UpdateUserEmailUseCase;
import com.erp.auth.application.usecase.UpdateUserPasswordUseCase;
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

import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
class UserControllerTest {

    @Mock
    private RegisterUserUseCase registerUserUseCase;
    @Mock
    private GetUserProfileUseCase getUserProfileUseCase;
    @Mock
    private ListTenantUsersUseCase listTenantUsersUseCase;
    @Mock
    private EnrollSecondFactorUseCase enrollSecondFactorUseCase;
    @Mock
    private ConfirmSecondFactorEnrollmentUseCase confirmSecondFactorEnrollmentUseCase;
    @Mock
    private GetUserByIdUseCase getUserByIdUseCase;
    @Mock
    private UpdateUserEmailUseCase updateUserEmailUseCase;
    @Mock
    private UpdateUserPasswordUseCase updateUserPasswordUseCase;

    private MockMvc mockMvc;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setUp() {
        UserController controller = new UserController(
                registerUserUseCase,
                getUserProfileUseCase,
                listTenantUsersUseCase,
                enrollSecondFactorUseCase,
                confirmSecondFactorEnrollmentUseCase,
                getUserByIdUseCase,
                updateUserEmailUseCase,
                updateUserPasswordUseCase
        );
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new GlobalRestExceptionHandler())
                .build();
    }

    @Test
    @DisplayName("GET /api/v1/users/{userId} returns 200 and user profile")
    void testGetUserById() throws Exception {
        UUID userId = UUID.randomUUID();
        UUID tenantId = UUID.randomUUID();
        UserResult result = new UserResult(
                userId, tenantId, "user@example.com", "Test User", false, Set.of("CUSTOMER"), Instant.now()
        );
        when(getUserByIdUseCase.getUserById(userId)).thenReturn(result);

        mockMvc.perform(get("/api/v1/users/" + userId)
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(userId.toString()))
                .andExpect(jsonPath("$.email").value("user@example.com"));
    }

    @Test
    @DisplayName("PUT /api/v1/users/{userId}/email returns 200 and new tokens")
    void testUpdateEmail() throws Exception {
        UUID userId = UUID.randomUUID();
        UUID tenantId = UUID.randomUUID();
        AuthResult authResult = new AuthResult(
                "new-access-token", "jti-99", "new-refresh-token", "Bearer",
                900, userId, tenantId, "updated@example.com", "Test User", Set.of("CUSTOMER")
        );
        when(updateUserEmailUseCase.updateEmail(any(UpdateUserEmailCommand.class))).thenReturn(authResult);

        mockMvc.perform(put("/api/v1/users/" + userId + "/email")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "email", "updated@example.com"
                        ))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("new-access-token"))
                .andExpect(jsonPath("$.email").value("updated@example.com"));
    }

    @Test
    @DisplayName("PUT /api/v1/users/{userId}/password returns 200")
    void testUpdatePassword() throws Exception {
        UUID userId = UUID.randomUUID();

        mockMvc.perform(put("/api/v1/users/" + userId + "/password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "currentPassword", "OldPassword123!",
                                "newPassword", "NewPassword456!"
                        ))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Password updated successfully"));

        verify(updateUserPasswordUseCase).updatePassword(any(UpdateUserPasswordCommand.class));
    }
}
