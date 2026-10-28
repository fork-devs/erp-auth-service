package com.erp.auth.domain.port;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Persistence for two-factor authentication: enrolled secrets and recovery codes.
 *
 * <p>The port interface operates on plaintext secrets: the application layer
 * remains agnostic of encryption details, while the infrastructure layer handles
 * transparent encryption and decryption without exposing keys or algorithms.
 */
public interface SecondFactorRepositoryPort {

    /**
     * Stores the enrolled secret. The persistence adapter encrypts the value before storage.
     *
     * @param userId the user identifier
     * @param secret the plaintext secret
     */
    void storeSecret(UUID userId, String secret);

    /**
     * Retrieves the enrolled secret in plaintext. Returns empty if the user has not enrolled 2FA.
     *
     * @param userId the user identifier
     * @return the plaintext secret, or empty if absent
     */
    Optional<String> findSecret(UUID userId);

    /**
     * Stores hashed recovery codes. Recovery codes are credentials: only hashes are stored.
     *
     * @param userId the user identifier
     * @param hashedCodes list of hashed recovery codes
     * @param expiresAt expiration timestamp
     */
    void storeRecoveryCodes(UUID userId, List<String> hashedCodes, Instant expiresAt);

    /**
     * Consumes a recovery code by marking it as used immediately to prevent reuse.
     *
     * @param userId the user identifier
     * @param hashedCode the hashed recovery code to consume
     * @return the consumed recovery code, or empty if nonexistent or already consumed
     */
    Optional<RecoveryCode> consumeRecoveryCode(UUID userId, String hashedCode);

    /**
     * Retrieves the counter of the last accepted time-step for the user.
     *
     * @param userId the user identifier
     * @return the last accepted counter, or empty if none recorded
     */
    Optional<Long> findLastAcceptedCounter(UUID userId);

    /**
     * Records the accepted time-step counter to prevent replay of the same code.
     *
     * @param userId the user identifier
     * @param counter the time-step counter
     */
    void recordAcceptedCounter(UUID userId, long counter);

    /**
     * Represents a consumed recovery code.
     *
     * @param id recovery code entity identifier
     * @param expiresAt expiration timestamp
     */
    record RecoveryCode(UUID id, Instant expiresAt) {
    }
}
