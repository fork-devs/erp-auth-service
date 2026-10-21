package com.erp.auth.infrastructure.config;

import com.erp.auth.application.service.AuthenticateUserService;
import com.erp.auth.application.service.PasswordResetService;
import com.erp.auth.application.service.RefreshTokenService;
import com.erp.auth.application.service.ListTenantUsersService;
import com.erp.auth.application.service.RegisterUserService;
import com.erp.auth.domain.port.PasswordEncoderPort;
import com.erp.auth.domain.port.PasswordResetTokenRepositoryPort;
import com.erp.auth.domain.port.RefreshTokenRepositoryPort;
import com.erp.auth.domain.port.RoleRepositoryPort;
import com.erp.auth.domain.port.TokenSignerPort;
import com.erp.auth.domain.port.UnitOfWork;
import com.erp.auth.domain.port.UserRepositoryPort;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;

@Configuration
public class ApplicationServiceConfig {

    @Bean
    public AuthenticateUserService authenticateUserService(
            UserRepositoryPort userRepositoryPort,
            RefreshTokenRepositoryPort refreshTokenRepositoryPort,
            PasswordEncoderPort passwordEncoderPort,
            TokenSignerPort tokenSignerPort,
            @Value("${erp.security.rate-limit.max-failed-attempts:5}") int maxFailedAttempts,
            @Value("${erp.security.rate-limit.lock-duration-minutes:15}") long lockDurationMinutes) {
        return new AuthenticateUserService(
                userRepositoryPort,
                refreshTokenRepositoryPort,
                passwordEncoderPort,
                tokenSignerPort,
                maxFailedAttempts,
                Duration.ofMinutes(lockDurationMinutes)
        );
    }

    @Bean
    public RefreshTokenService refreshTokenService(
            RefreshTokenRepositoryPort refreshTokenRepositoryPort,
            UserRepositoryPort userRepositoryPort,
            TokenSignerPort tokenSignerPort) {
        return new RefreshTokenService(
                refreshTokenRepositoryPort,
                userRepositoryPort,
                tokenSignerPort
        );
    }

    @Bean
    public RegisterUserService registerUserService(
            UserRepositoryPort userRepositoryPort,
            RoleRepositoryPort roleRepositoryPort,
            PasswordEncoderPort passwordEncoderPort,
            UnitOfWork unitOfWork) {
        return new RegisterUserService(
                userRepositoryPort,
                roleRepositoryPort,
                passwordEncoderPort,
                unitOfWork
        );
    }

    @Bean
    public ListTenantUsersService listTenantUsersService(
            UserRepositoryPort userRepositoryPort) {
        return new ListTenantUsersService(userRepositoryPort);
    }

    @Bean
    public PasswordResetService passwordResetService(
            UserRepositoryPort userRepositoryPort,
            PasswordResetTokenRepositoryPort passwordResetTokenRepositoryPort,
            RefreshTokenRepositoryPort refreshTokenRepositoryPort,
            PasswordEncoderPort passwordEncoderPort,
            TokenSignerPort tokenSignerPort) {
        return new PasswordResetService(
                userRepositoryPort,
                passwordResetTokenRepositoryPort,
                refreshTokenRepositoryPort,
                passwordEncoderPort,
                tokenSignerPort
        );
    }
}
