package com.erp.auth.domain.model;

/**
 * Password policy.
 *
 * <p>Two rules enforced above conventional practices:
 *
 * <ul>
 *   <li>A parametric minimum length, defaulting to fourteen characters.
 *       Below eight characters, brute force attacks can crack passwords very quickly.</li>
 *   <li>Rejection of the most common passwords. A password such as
 *       "123456" is never protected by length: it appears at the top
 *       of every password dictionary list.</li>
 * </ul>
 */
public final class PasswordPolicy {

    /**
     * Most common passwords. The list is intentionally concise: it covers
     * entries at the top of common password leak dumps, without being an exhaustive dictionary.
     */
    private static final java.util.Set<String> MAS_USADAS = java.util.Set.of(
            "123456", "123456789", "12345678", "1234567890", "password", "contrasena",
            "1234567", "qwerty", "abc123", "111111", "123123", "admin",
            "welcome", "iloveyou", "monkey", "dragon", "sunshine", "princess", "football",
            "charlie", "access", "master", "michael", "superman", "batman", "trustno1",
            "contrasena1", "123456a", "pass123", "administrador", "root", "toor");

    private final int minLength;

    public PasswordPolicy(int minLength) {
        if (minLength < 8) {
            throw new IllegalArgumentException(
                    "La longitud minima de la contrasena no puede ser inferior a 8: " + minLength);
        }
        this.minLength = minLength;
    }

    /**
     * Validates a password against this policy.
     *
     * @param password the password to evaluate
     * @return rejection reason, or empty if the password meets the policy
     */
    public java.util.Optional<String> reject(String password) {
        if (password == null || password.isBlank()) {
            return java.util.Optional.of("La contraseña es obligatoria");
        }
        if (password.length() < minLength) {
            return java.util.Optional.of(
                    "La contraseña debe tener al menos " + minLength + " caracteres");
        }
        if (MAS_USADAS.contains(password.toLowerCase())) {
            return java.util.Optional.of("La contraseña es demasiado habitual");
        }
        return java.util.Optional.empty();
    }

    public int minLength() {
        return minLength;
    }
}
