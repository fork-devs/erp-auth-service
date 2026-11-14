package com.erp.auth.application;

import com.erp.auth.application.service.SecondFactorEnrollmentService;
import com.erp.auth.domain.exception.InvalidSecondFactorCodeException;
import com.erp.auth.domain.model.User;
import com.erp.auth.domain.port.NotificationPort;
import com.erp.auth.domain.port.SecondFactorPort;
import com.erp.auth.domain.port.SecondFactorRepositoryPort;
import com.erp.auth.domain.port.TokenSignerPort;
import com.erp.auth.domain.port.UserRepositoryPort;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.domain.valueobject.PasswordHash;
import com.erp.auth.domain.valueobject.TenantId;
import com.erp.auth.infrastructure.security.mfa.TotpSecondFactorAdapter;
import com.erp.auth.support.DirectUnitOfWork;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("Application - SecondFactor Replay Protection & Rate Limit Test")
class SecondFactorReplayProtectionTest {

    @Mock
    private SecondFactorPort secondFactorPort;

    @Mock
    private SecondFactorRepositoryPort secondFactorRepositoryPort;

    @Mock
    private UserRepositoryPort userRepositoryPort;

    @Mock
    private NotificationPort notificationPort;

    @Mock
    private TotpSecondFactorAdapter totpAdapter;

    @Mock
    private TokenSignerPort tokenSignerPort;

    private SecondFactorEnrollmentService service;
    private User sampleUser;
    private UUID userId;
    private UUID tenantId;

    @BeforeEach
    void setUp() {
        userId = UUID.randomUUID();
        tenantId = UUID.randomUUID();
        sampleUser = new User(
                userId,
                new TenantId(tenantId),
                new Email("mechanic@driveos.pe"),
                new PasswordHash("hashed-password-123"),
                "Mechanic User",
                false,
                0,
                null,
                Set.of(),
                Instant.now()
        );

        service = new SecondFactorEnrollmentService(
                secondFactorPort,
                secondFactorRepositoryPort,
                userRepositoryPort,
                notificationPort,
                totpAdapter,
                tokenSignerPort,
                DirectUnitOfWork.INSTANCE
        );
    }

    @Test
    @DisplayName("Should reject TOTP code if counter is less than or equal to last accepted counter (replay protection)")
    void shouldRejectReplayedTotpCode() {
        when(userRepositoryPort.findByIdAndTenantId(userId, new TenantId(tenantId)))
                .thenReturn(Optional.of(sampleUser));
        when(secondFactorRepositoryPort.findSecret(userId)).thenReturn(Optional.of("JBSWY3DPEHPK3PXP"));

        long consumedCounter = 55555L;
        when(secondFactorPort.verify(eq("JBSWY3DPEHPK3PXP"), eq("123456"), any(Instant.class)))
                .thenReturn(Optional.of(consumedCounter));
        // Simulate that counter 55555L was ALREADY recorded previously
        when(secondFactorRepositoryPort.findLastAcceptedCounter(userId))
                .thenReturn(Optional.of(consumedCounter));

        assertThatThrownBy(() -> service.confirm(userId, tenantId, "123456"))
                .isInstanceOf(InvalidSecondFactorCodeException.class)
                .hasMessageContaining("previamente utilizado");

        verify(secondFactorRepositoryPort, never()).recordAcceptedCounter(any(), anyLong());
    }

    @Test
    @DisplayName("Should lock account when confirmation fails repeatedly")
    void shouldLockAccountAfterRepeatedConfirmationFailures() {
        when(userRepositoryPort.findByIdAndTenantId(userId, new TenantId(tenantId)))
                .thenReturn(Optional.of(sampleUser));
        when(secondFactorRepositoryPort.findSecret(userId)).thenReturn(Optional.of("JBSWY3DPEHPK3PXP"));
        when(secondFactorPort.verify(any(), any(), any())).thenReturn(Optional.empty());

        // Perform 5 failed attempts
        for (int i = 0; i < 4; i++) {
            assertThatThrownBy(() -> service.confirm(userId, tenantId, "000000"))
                    .isInstanceOf(InvalidSecondFactorCodeException.class);
        }

        // 5th attempt locks the account
        assertThatThrownBy(() -> service.confirm(userId, tenantId, "000000"))
                .isInstanceOf(InvalidSecondFactorCodeException.class)
                .hasMessageContaining("bloqueada");
    }
}
