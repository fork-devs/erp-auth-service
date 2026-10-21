package com.erp.auth.domain.model;

/**
 * Politica de contrasenas.
 *
 * <p>Dos reglas, y las dos por encima de la costumbre:
 *
 * <ul>
 *   <li>Una longitud minima parametrica, con un valor por defecto de catorce
 *       caracteres. Por debajo de ocho, un atacante con capacidad de fuerza
 *       bruta la resuelve en un tiempo ridiculo.</li>
 *   <li>Un rechazo de las contrasenas mas usadas. Una contrasena como
 *       "123456" no esta protected por ninguna longitud: aparece en la
 *       primera pagina de cualquier diccionario.</li>
 * </ul>
 */
public final class PasswordPolicy {

    /**
     * Contrasenas mas usadas. La lista es corta a proposito: cubre las que
     * aparecen en la cima de cualquier filtrado de contrasenas, sin llegar a
     * ser un diccionario.
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
     * Comprueba una contrasena.
     *
     * @return el motivo del rechazo, o vacio si la contrasena es aceptable
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
