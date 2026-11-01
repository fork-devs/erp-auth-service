package com.erp.auth.application.service;

import com.erp.auth.application.usecase.ConfirmSecondFactorEnrollmentUseCase;
import com.erp.auth.application.usecase.EnrollSecondFactorUseCase;
import com.erp.auth.domain.exception.InvalidSecondFactorCodeException;
import com.erp.auth.domain.exception.UserNotFoundException;
import com.erp.auth.domain.model.NotificationMessage;
import com.erp.auth.domain.model.User;
import com.erp.auth.domain.port.NotificationPort;
import com.erp.auth.domain.port.SecondFactorPort;
import com.erp.auth.domain.port.SecondFactorRepositoryPort;
import com.erp.auth.domain.port.TokenSignerPort;
import com.erp.auth.domain.port.UnitOfWork;
import com.erp.auth.domain.port.UserRepositoryPort;
import com.erp.auth.domain.valueobject.TenantId;
import com.erp.auth.infrastructure.security.mfa.TotpSecondFactorAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Second-factor authentication enrollment service.
 *
 * <p>Enrollment follows a two-step flow: a secret and recovery codes are generated
 * and delivered to the user via notification channels, and the user verifies binding
 * with a valid code. 2FA is only ENABLED once this confirmation succeeds.
 *
 * <p>Neither secret nor recovery codes are returned in the API response to prevent
 * exposing credentials directly over HTTP responses.
 */
public class SecondFactorEnrollmentService
        implements EnrollSecondFactorUseCase, ConfirmSecondFactorEnrollmentUseCase {

    private static final Logger log = LoggerFactory.getLogger(SecondFactorEnrollmentService.class);

    /** Validity duration of generated recovery codes. */
    private static final Duration RECOVERY_CODE_VALIDITY = Duration.ofHours(24);

    /** Number of recovery codes generated per enrollment. */
    private static final int RECOVERY_CODE_COUNT = 8;

    private final SecondFactorPort secondFactorPort;
    private final SecondFactorRepositoryPort secondFactorRepositoryPort;
    private final UserRepositoryPort userRepositoryPort;
    private final NotificationPort notificationPort;
    private final TotpSecondFactorAdapter totpAdapter;
    private final TokenSignerPort tokenSignerPort;
    private final UnitOfWork unitOfWork;

    public SecondFactorEnrollmentService(
            SecondFactorPort secondFactorPort,
            SecondFactorRepositoryPort secondFactorRepositoryPort,
            UserRepositoryPort userRepositoryPort,
            NotificationPort notificationPort,
            TotpSecondFactorAdapter totpAdapter,
            TokenSignerPort tokenSignerPort,
            UnitOfWork unitOfWork) {
        this.secondFactorPort = secondFactorPort;
        this.secondFactorRepositoryPort = secondFactorRepositoryPort;
        this.userRepositoryPort = userRepositoryPort;
        this.notificationPort = notificationPort;
        this.totpAdapter = totpAdapter;
        this.tokenSignerPort = tokenSignerPort;
        this.unitOfWork = unitOfWork;
    }

    @Override
    public void enroll(UUID userId, UUID tenantId) {
        User user = userRepositoryPort.findByIdAndTenantId(userId, new TenantId(tenantId))
                .orElseThrow(() -> new UserNotFoundException(userId.toString()));

        SecondFactorPort.SecondFactorSecret enrolado = secondFactorPort.enroll();

        List<String> codigos = java.util.stream.IntStream.range(0, RECOVERY_CODE_COUNT)
                .mapToObj(i -> totpAdapter.generarCodigoDeRecuperacion())
                .toList();

        unitOfWork.runInTransaction(() -> {
            secondFactorRepositoryPort.storeSecret(userId, enrolado.secret());
            secondFactorRepositoryPort.storeRecoveryCodes(
                    userId,
                    codigos.stream().map(this::hash).toList(),
                    Instant.now().plus(RECOVERY_CODE_VALIDITY));
        });

        // Delivery is performed OUTSIDE the transaction boundary: external notification
        // calls should not keep database transactions open.
        notificationPort.deliver(NotificationMessage.of(
                user.getEmail().getValue(),
                "Activa tu segundo factor de autenticacion",
                "Enlaza esta clave en tu aplicacion autenticadora: " + enrolado.uri()
                        + "\n\nCodigos de recuperacion (cada uno sirve una sola vez):\n"
                        + String.join("\n", codigos)));

        log.info("Segundo factor enrolado para el usuario {} del taller {}", userId, tenantId);
    }

    @Override
    public void confirm(UUID userId, UUID tenantId, String code) {
        User user = userRepositoryPort.findByIdAndTenantId(userId, new TenantId(tenantId))
                .orElseThrow(() -> new UserNotFoundException(userId.toString()));

        String secreto = secondFactorRepositoryPort.findSecret(userId)
                .orElseThrow(() -> new InvalidSecondFactorCodeException(
                        "El usuario no tiene ningun segundo factor enrolado"));

        if (secondFactorPort.verify(secreto, code, Instant.now()).isEmpty()) {
            throw new InvalidSecondFactorCodeException();
        }

        user.enableSecondFactor();
        unitOfWork.runInTransaction(() -> userRepositoryPort.save(user));

        log.info("Segundo factor confirmado y habilitado para el usuario {}", userId);
    }

    /**
     * Recovery codes are credentials: only cryptographic hashes are stored.
     * Reuses the token signer hash algorithm, matching refresh token storage.
     */
    private String hash(String codigo) {
        return tokenSignerPort.hashToken(codigo);
    }
}
