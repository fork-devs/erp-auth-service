package com.erp.auth.interfaces.rest.controller;

import com.erp.auth.application.dto.command.ForgotPasswordCommand;
import com.erp.auth.application.dto.command.LoginCommand;
import com.erp.auth.application.dto.command.RefreshTokenCommand;
import com.erp.auth.application.dto.command.ResetPasswordCommand;
import com.erp.auth.application.dto.result.AuthResult;
import com.erp.auth.application.usecase.AuthenticateUserUseCase;
import com.erp.auth.application.usecase.PasswordResetUseCase;
import com.erp.auth.application.usecase.RefreshTokenUseCase;
import com.erp.auth.application.usecase.RevokeTokenUseCase;
import com.erp.auth.infrastructure.persistence.rls.TenantContextScope;
import com.erp.auth.interfaces.rest.dto.request.ForgotPasswordRequest;
import com.erp.auth.interfaces.rest.dto.request.LoginRequest;
import com.erp.auth.interfaces.rest.dto.request.RefreshTokenRequest;
import com.erp.auth.interfaces.rest.dto.request.ResetPasswordRequest;
import com.erp.auth.interfaces.rest.dto.response.AuthResponse;
import com.erp.auth.interfaces.rest.dto.response.MessageResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@Tag(name = "Authentication", description = "Endpoints para inicio de sesión, rotación de tokens y recuperación de clave")
public class AuthController {

    private final AuthenticateUserUseCase authenticateUserUseCase;
    private final RefreshTokenUseCase refreshTokenUseCase;
    private final RevokeTokenUseCase revokeTokenUseCase;
    private final PasswordResetUseCase passwordResetUseCase;

    public AuthController(
            AuthenticateUserUseCase authenticateUserUseCase,
            RefreshTokenUseCase refreshTokenUseCase,
            RevokeTokenUseCase revokeTokenUseCase,
            PasswordResetUseCase passwordResetUseCase) {
        this.authenticateUserUseCase = authenticateUserUseCase;
        this.refreshTokenUseCase = refreshTokenUseCase;
        this.revokeTokenUseCase = revokeTokenUseCase;
        this.passwordResetUseCase = passwordResetUseCase;
    }

    @PostMapping("/login")
    @Operation(summary = "Iniciar sesión", description = "Valida credenciales, aplica control de fuerza bruta y emite Access Token (JWT 15m) + Refresh Token")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        LoginCommand command = new LoginCommand(request.email(), request.password(), request.tenantId());
        AuthResult result;
        try (TenantContextScope scope = TenantContextScope.forTenant(request.tenantId())) {
            result = authenticateUserUseCase.authenticate(command);
        }

        return ResponseEntity.ok(new AuthResponse(
                result.accessToken(),
                result.refreshToken(),
                result.tokenType(),
                result.expiresInSeconds(),
                result.userId(),
                result.tenantId(),
                result.email(),
                result.fullName(),
                result.roles()
        ));
    }

    @PostMapping("/refresh")
    @Operation(summary = "Rotar Refresh Token", description = "Invalida el token de actualización previo y emite un nuevo par Access Token + Refresh Token")
    public ResponseEntity<AuthResponse> refresh(@Valid @RequestBody RefreshTokenRequest request) {
        RefreshTokenCommand command = new RefreshTokenCommand(request.refreshToken(), request.tenantId());
        AuthResult result;
        try (TenantContextScope scope = TenantContextScope.forTenant(request.tenantId())) {
            result = refreshTokenUseCase.refreshToken(command);
        }

        return ResponseEntity.ok(new AuthResponse(
                result.accessToken(),
                result.refreshToken(),
                result.tokenType(),
                result.expiresInSeconds(),
                result.userId(),
                result.tenantId(),
                result.email(),
                result.fullName(),
                result.roles()
        ));
    }

    @PostMapping("/logout")
    @Operation(summary = "Cerrar sesión", description = "Revoca el Refresh Token activo")
    public ResponseEntity<MessageResponse> logout(@Valid @RequestBody RefreshTokenRequest request) {
        try (TenantContextScope scope = TenantContextScope.forTenant(request.tenantId())) {
            revokeTokenUseCase.revokeToken(request.refreshToken());
        }
        return ResponseEntity.ok(MessageResponse.of("Sesión cerrada exitosamente"));
    }

    @PostMapping("/forgot-password")
    @Operation(summary = "Solicitar recuperación de contraseña", description = "Genera un token seguro de un solo uso con vigencia de 30 minutos")
    public ResponseEntity<MessageResponse> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        try (TenantContextScope scope = TenantContextScope.forTenant(request.tenantId())) {
            passwordResetUseCase.requestPasswordReset(new ForgotPasswordCommand(request.email(), request.tenantId()));
        }
        return ResponseEntity.ok(MessageResponse.of("Si el correo está registrado, se ha enviado un enlace de recuperación"));
    }

    @PostMapping("/reset-password")
    @Operation(summary = "Restablecer contraseña", description = "Aplica nueva contraseña con el token de recuperación y revoca sesiones previas")
    public ResponseEntity<MessageResponse> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        try (TenantContextScope scope = TenantContextScope.forTenant(request.tenantId())) {
            passwordResetUseCase.resetPassword(
                    new ResetPasswordCommand(request.token(), request.newPassword(), request.tenantId()));
        }
        return ResponseEntity.ok(MessageResponse.of("Contraseña actualizada exitosamente"));
    }
}
