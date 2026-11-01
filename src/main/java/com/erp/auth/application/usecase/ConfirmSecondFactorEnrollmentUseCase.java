package com.erp.auth.application.usecase;

import java.util.UUID;

/**
 * Confirmation of second-factor authentication enrollment.
 *
 * <p>Enrollment is not completed until the user verifies that their authenticator
 * app is properly bound by submitting a valid TOTP code.
 */
public interface ConfirmSecondFactorEnrollmentUseCase {

    /**
     * Confirms 2FA enrollment using a verification code.
     *
     * @param userId user identifier
     * @param tenantId tenant identifier
     * @param code verification code
     * @throws com.erp.auth.domain.exception.InvalidSecondFactorCodeException
     *         if the code is invalid or expired
     */
    void confirm(UUID userId, UUID tenantId, String code);
}
