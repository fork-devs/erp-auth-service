package com.erp.auth.interfaces.rest.controller;

import com.erp.auth.application.dto.command.AcceptInvitationCommand;
import com.erp.auth.application.dto.command.ForgotPasswordCommand;
import com.erp.auth.application.dto.command.GoogleLoginCommand;
import com.erp.auth.application.dto.command.LoginCommand;
import com.erp.auth.application.dto.command.RefreshTokenCommand;
import com.erp.auth.application.dto.command.ResetPasswordCommand;
import com.erp.auth.application.dto.command.SendOtpCommand;
import com.erp.auth.application.dto.command.VerifyOtpCommand;
import com.erp.auth.application.dto.result.AuthResult;
import com.erp.auth.application.dto.result.InvitationDetailsResult;
import com.erp.auth.application.usecase.AcceptInvitationUseCase;
import com.erp.auth.application.usecase.AuthenticateUserUseCase;
import com.erp.auth.application.usecase.GetInvitationUseCase;
import com.erp.auth.application.usecase.GoogleLoginUseCase;
import com.erp.auth.application.usecase.PasswordResetUseCase;
import com.erp.auth.application.usecase.RefreshTokenUseCase;
import com.erp.auth.application.usecase.RevokeAccessTokenUseCase;
import com.erp.auth.application.usecase.RevokeTokenUseCase;
import com.erp.auth.application.usecase.SendOtpUseCase;
import com.erp.auth.application.usecase.VerifyOtpUseCase;
import com.erp.auth.infrastructure.persistence.rls.TenantContextScope;
import com.erp.auth.interfaces.rest.dto.request.AcceptInvitationRequest;
import com.erp.auth.interfaces.rest.dto.request.ForgotPasswordRequest;
import com.erp.auth.interfaces.rest.dto.request.GoogleLoginRequest;
import com.erp.auth.interfaces.rest.dto.request.LoginRequest;
import com.erp.auth.interfaces.rest.dto.request.RefreshTokenRequest;
import com.erp.auth.interfaces.rest.dto.request.ResetPasswordRequest;
import com.erp.auth.interfaces.rest.dto.request.SendOtpRequest;
import com.erp.auth.interfaces.rest.dto.request.VerifyOtpRequest;
import com.erp.auth.interfaces.rest.dto.response.AuthResponse;
import com.erp.auth.interfaces.rest.dto.response.InvitationDetailsResponse;
import com.erp.auth.interfaces.rest.dto.response.MessageResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/authentication")
@Tag(name = "Authentication Canonical", description = "Endpoints canónicos de autenticación y gestión de sesiones")
public class AuthenticationController {

    private final AuthenticateUserUseCase authenticateUserUseCase;
    private final GoogleLoginUseCase googleLoginUseCase;
    private final RefreshTokenUseCase refreshTokenUseCase;
    private final RevokeAccessTokenUseCase revokeAccessTokenUseCase;
    private final RevokeTokenUseCase revokeTokenUseCase;
    private final PasswordResetUseCase passwordResetUseCase;
    private final SendOtpUseCase sendOtpUseCase;
    private final VerifyOtpUseCase verifyOtpUseCase;
    private final AcceptInvitationUseCase acceptInvitationUseCase;
    private final GetInvitationUseCase getInvitationUseCase;

    public AuthenticationController(
            AuthenticateUserUseCase authenticateUserUseCase,
            GoogleLoginUseCase googleLoginUseCase,
            RefreshTokenUseCase refreshTokenUseCase,
            RevokeAccessTokenUseCase revokeAccessTokenUseCase,
            RevokeTokenUseCase revokeTokenUseCase,
            PasswordResetUseCase passwordResetUseCase,
            SendOtpUseCase sendOtpUseCase,
            VerifyOtpUseCase verifyOtpUseCase) {
        this(authenticateUserUseCase, googleLoginUseCase, refreshTokenUseCase,
                revokeAccessTokenUseCase, revokeTokenUseCase, passwordResetUseCase,
                sendOtpUseCase, verifyOtpUseCase, null, null);
    }

    @org.springframework.beans.factory.annotation.Autowired
    public AuthenticationController(
            AuthenticateUserUseCase authenticateUserUseCase,
            GoogleLoginUseCase googleLoginUseCase,
            RefreshTokenUseCase refreshTokenUseCase,
            RevokeAccessTokenUseCase revokeAccessTokenUseCase,
            RevokeTokenUseCase revokeTokenUseCase,
            PasswordResetUseCase passwordResetUseCase,
            SendOtpUseCase sendOtpUseCase,
            VerifyOtpUseCase verifyOtpUseCase,
            @org.springframework.beans.factory.annotation.Autowired(required = false) AcceptInvitationUseCase acceptInvitationUseCase,
            @org.springframework.beans.factory.annotation.Autowired(required = false) GetInvitationUseCase getInvitationUseCase) {
        this.authenticateUserUseCase = authenticateUserUseCase;
        this.googleLoginUseCase = googleLoginUseCase;
        this.refreshTokenUseCase = refreshTokenUseCase;
        this.revokeAccessTokenUseCase = revokeAccessTokenUseCase;
        this.revokeTokenUseCase = revokeTokenUseCase;
        this.passwordResetUseCase = passwordResetUseCase;
        this.sendOtpUseCase = sendOtpUseCase;
        this.verifyOtpUseCase = verifyOtpUseCase;
        this.acceptInvitationUseCase = acceptInvitationUseCase;
        this.getInvitationUseCase = getInvitationUseCase;
    }

    @PostMapping("/sessions")
    @PreAuthorize("permitAll()")
    @Operation(summary = "Iniciar sesión (Sessions)", description = "Autentica a un usuario mediante credenciales emitiendo Access Token + Refresh Token")
    public ResponseEntity<AuthResponse> createSession(@Valid @RequestBody LoginRequest request) {
        LoginCommand command = new LoginCommand(request.email(), request.password(), request.tenantId());
        AuthResult result;
        try (TenantContextScope scope = TenantContextScope.forTenant(request.tenantId())) {
            result = authenticateUserUseCase.authenticate(command);
        }

        return ResponseEntity.ok(toAuthResponse(result));
    }

    @PostMapping("/sessions/google")
    @PreAuthorize("permitAll()")
    @Operation(summary = "Login con Google OAuth", description = "Autentica usuario con Google ID Token y auto-aprovisiona cuenta si es nueva")
    public ResponseEntity<AuthResponse> loginWithGoogle(@Valid @RequestBody GoogleLoginRequest request) {
        GoogleLoginCommand command = new GoogleLoginCommand(request.idToken(), request.tenantId());
        AuthResult result;
        try (TenantContextScope scope = TenantContextScope.forTenant(request.tenantId())) {
            result = googleLoginUseCase.loginWithGoogle(command);
        }

        return ResponseEntity.ok(toAuthResponse(result));
    }

    @PostMapping("/sessions/refresh")
    @PreAuthorize("permitAll()")
    @Operation(summary = "Refrescar sesión", description = "Intercambia refresh token por nuevo par de credenciales con rotación de un solo uso")
    public ResponseEntity<AuthResponse> refreshSession(@Valid @RequestBody RefreshTokenRequest request) {
        RefreshTokenCommand command = new RefreshTokenCommand(request.refreshToken(), request.tenantId());
        AuthResult result;
        try (TenantContextScope scope = TenantContextScope.forTenant(request.tenantId())) {
            result = refreshTokenUseCase.refreshToken(command);
        }

        return ResponseEntity.ok(toAuthResponse(result));
    }

    @DeleteMapping("/sessions")
    @PreAuthorize("permitAll()")
    @Operation(summary = "Cerrar sesión (Logout)", description = "Revoca el refresh token y access token opcional enviado")
    public ResponseEntity<Void> logoutSession(
            @RequestBody(required = false) RefreshTokenRequest request,
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
        if (request != null && request.refreshToken() != null && !request.refreshToken().isBlank()) {
            try (TenantContextScope scope = TenantContextScope.forTenant(request.tenantId())) {
                revokeTokenUseCase.revokeToken(request.refreshToken());
            }
        }

        if (authorization != null && authorization.startsWith("Bearer ")) {
            revokeAccessTokenUseCase.revokeAccessToken(authorization.substring(7).trim());
        }

        return ResponseEntity.noContent().build();
    }

    @PostMapping("/password-recoveries")
    @PreAuthorize("permitAll()")
    @Operation(summary = "Solicitar recuperación de contraseña", description = "Envía email con enlace de recuperación con respuesta anti-enumeración")
    public ResponseEntity<MessageResponse> requestPasswordRecovery(@Valid @RequestBody ForgotPasswordRequest request) {
        try (TenantContextScope scope = TenantContextScope.forTenant(request.tenantId())) {
            passwordResetUseCase.requestPasswordReset(new ForgotPasswordCommand(request.email(), request.tenantId()));
        }
        return ResponseEntity.ok(MessageResponse.of("Si el correo está registrado, se ha enviado un enlace de recuperación"));
    }

    @PostMapping("/password-resets")
    @PreAuthorize("permitAll()")
    @Operation(summary = "Restablecer contraseña", description = "Aplica nueva contraseña con token de recuperación y revoca sesiones previas")
    public ResponseEntity<MessageResponse> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        try (TenantContextScope scope = TenantContextScope.forTenant(request.tenantId())) {
            passwordResetUseCase.resetPassword(
                    new ResetPasswordCommand(request.token(), request.newPassword(), request.tenantId()));
        }
        return ResponseEntity.ok(MessageResponse.of("Password updated successfully"));
    }

    @PostMapping("/otp/send")
    @PreAuthorize("permitAll()")
    @Operation(summary = "Enviar código OTP", description = "Genera y envía un código numérico temporal de 6 dígitos al correo especificado")
    public ResponseEntity<MessageResponse> sendOtp(@Valid @RequestBody SendOtpRequest request) {
        sendOtpUseCase.sendOtp(new SendOtpCommand(request.email()));
        return ResponseEntity.ok(MessageResponse.of("Código OTP enviado exitosamente"));
    }

    @PostMapping("/otp/verify")
    @PreAuthorize("permitAll()")
    @Operation(summary = "Verificar código OTP", description = "Valida el código temporal de 6 dígitos presentado por el usuario")
    public ResponseEntity<MessageResponse> verifyOtp(@Valid @RequestBody VerifyOtpRequest request) {
        verifyOtpUseCase.verifyOtp(new VerifyOtpCommand(request.email(), request.code()));
        return ResponseEntity.ok(MessageResponse.of("Código OTP verificado exitosamente"));
    }

    @GetMapping("/invitations/{token}")
    @PreAuthorize("permitAll()")
    @Operation(summary = "Consultar invitación por token", description = "Valida y retorna los datos de una invitación activa")
    public ResponseEntity<InvitationDetailsResponse> getInvitation(@PathVariable String token) {
        if (getInvitationUseCase == null) {
            throw new IllegalStateException("GetInvitationUseCase is not configured");
        }
        InvitationDetailsResult result = getInvitationUseCase.getInvitation(token);
        return ResponseEntity.ok(new InvitationDetailsResponse(
                result.id(),
                result.tenantId(),
                result.email(),
                result.fullName(),
                result.role(),
                result.valid(),
                result.expiresAt()
        ));
    }

    @PostMapping("/invitations/accept")
    @PreAuthorize("permitAll()")
    @Operation(summary = "Aceptar invitación y definir contraseña", description = "Activa la cuenta del colaborador y emite credenciales de sesión")
    public ResponseEntity<AuthResponse> acceptInvitation(@Valid @RequestBody AcceptInvitationRequest request) {
        if (acceptInvitationUseCase == null) {
            throw new IllegalStateException("AcceptInvitationUseCase is not configured");
        }
        InvitationDetailsResult details = getInvitationUseCase.getInvitation(request.token());
        AuthResult result;
        try (TenantContextScope scope = TenantContextScope.forTenant(details.tenantId())) {
            result = acceptInvitationUseCase.accept(
                    new AcceptInvitationCommand(request.token(), request.password()));
        }
        return ResponseEntity.ok(toAuthResponse(result));
    }

    private AuthResponse toAuthResponse(AuthResult result) {
        return new AuthResponse(
                result.accessToken(),
                result.accessTokenId(),
                result.refreshToken(),
                result.tokenType(),
                result.expiresInSeconds(),
                result.userId(),
                result.tenantId(),
                result.email(),
                result.fullName(),
                result.roles()
        );
    }
}
