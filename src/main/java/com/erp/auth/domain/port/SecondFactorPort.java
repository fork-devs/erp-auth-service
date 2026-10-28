package com.erp.auth.domain.port;

/**
 * Two-factor authentication: time-based one-time passwords (TOTP).
 *
 * <p>This is a domain port decoupled from any specific verification library
 * or framework. The infrastructure implementation handles code verification mechanics.
 *
 * <p>Secret enrollment and code verification are the only operations required
 * by the domain; persistence and replay tracking belong to infrastructure ports.
 */
public interface SecondFactorPort {

    /**
     * Generates a new secret and its enrollment URI.
     *
     * @return the Base32 secret displayed to the user along with its otpauth URI
     */
    SecondFactorSecret enroll();

    /**
     * Verifies a code against a secret.
     *
     * @param secret  the secret enrolled by the user
     * @param code    the code submitted by the user
     * @param at      the instant at which verification takes place, ensuring deterministic evaluation
     * @return the accepted time-step counter, or empty if the code is invalid.
     *         The counter prevents replay attacks within the valid time window.
     */
    java.util.Optional<Long> verify(String secret, String code, java.time.Instant at);

    /**
     * Second-factor secret and its enrollment URI.
     *
     * @param secret the secret in Base32
     * @param uri    the otpauth:// URI used by authenticator apps to enroll
     */
    record SecondFactorSecret(String secret, String uri) {
    }
}
