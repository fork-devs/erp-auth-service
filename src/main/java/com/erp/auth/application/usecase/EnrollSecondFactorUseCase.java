package com.erp.auth.application.usecase;

import java.util.UUID;

/**
 * Second-factor authentication enrollment.
 *
 * <p>Generates the secret and recovery codes, delivering them to the user via
 * the notification channel. Credentials are NOT returned in the API response
 * to prevent leakage to unauthorized requesters.
 */
public interface EnrollSecondFactorUseCase {

    /**
     * Generates secret and recovery codes and delivers them to the user's registered email.
     *
     * @param userId the user being enrolled
     * @param tenantId the workshop tenant they belong to
     */
    void enroll(UUID userId, UUID tenantId);
}
