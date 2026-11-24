package com.erp.auth.interfaces.rest.controller;

import com.erp.auth.application.dto.command.LoginCommand;
import com.erp.auth.application.dto.command.RegisterUserCommand;
import com.erp.auth.application.dto.result.AuthResult;
import com.erp.auth.application.dto.result.UserResult;
import com.erp.auth.application.usecase.*;
import com.erp.auth.domain.model.OtpPurpose;
import com.erp.auth.domain.model.OtpVerification;
import com.erp.auth.domain.port.OtpVerificationRepositoryPort;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.domain.valueobject.OtpCodeHash;
import com.erp.auth.interfaces.rest.advice.GlobalRestExceptionHandler;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class PublicRegistrationControllerTest {

    @Test
    @DisplayName("POST /api/v1/authentication/registrations registers OWNER after OTP verification and returns 201")
    void registerOwner_WithVerifiedOtp_Returns201() throws Exception {
        AuthenticateUserUseCase authUseCase = mock(AuthenticateUserUseCase.class);
        RegisterUserUseCase registerUseCase = mock(RegisterUserUseCase.class);
        OtpVerificationRepositoryPort otpRepo = mock(OtpVerificationRepositoryPort.class);

        Email email = Email.of("owner@driveos.pe");
        Instant now = Instant.now();
        OtpVerification verifiedOtp = OtpVerification.reconstitute(
                com.erp.auth.domain.valueobject.OtpVerificationId.generate(),
                null, null, email, OtpPurpose.EMAIL_VERIFICATION,
                OtpCodeHash.of("a".repeat(64)), 0, true,
                now.plus(Duration.ofMinutes(10)), now
        );

        when(otpRepo.findLatestByEmail(email)).thenReturn(Optional.of(verifiedOtp));
        UUID userId = UUID.randomUUID();
        UUID tenantId = UUID.randomUUID();
        when(registerUseCase.register(any(RegisterUserCommand.class)))
                .thenReturn(new UserResult(userId, tenantId, email.value(), "Aldo Owner", false, Set.of("WORKSHOP_ADMIN"), Instant.now()));
        when(authUseCase.authenticate(any(LoginCommand.class)))
                .thenReturn(new AuthResult("acc-jwt", "jti-1", "ref-tok", "Bearer", 3600L, userId, tenantId, email.value(), "Aldo Owner", Set.of("WORKSHOP_ADMIN")));

        AuthenticationController controller = new AuthenticationController(
                authUseCase, mock(GoogleLoginUseCase.class), mock(RefreshTokenUseCase.class),
                mock(RevokeAccessTokenUseCase.class), mock(RevokeTokenUseCase.class),
                mock(PasswordResetUseCase.class), mock(SendOtpUseCase.class), mock(VerifyOtpUseCase.class),
                null, null, registerUseCase, otpRepo
        );

        MockMvc mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new GlobalRestExceptionHandler())
                .build();

        mockMvc.perform(post("/api/v1/authentication/registrations")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "email": "owner@driveos.pe",
                                  "password": "SecurePassword2026!",
                                  "fullName": "Aldo Owner",
                                  "accountType": "OWNER"
                                }
                                """))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.accessToken").value("acc-jwt"))
                .andExpect(jsonPath("$.roles[0]").value("WORKSHOP_ADMIN"));
    }
}
