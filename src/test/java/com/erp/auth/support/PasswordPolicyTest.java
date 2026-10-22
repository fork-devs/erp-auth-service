package com.erp.auth.support;

import com.erp.auth.domain.model.PasswordPolicy;
import com.erp.auth.infrastructure.security.crypto.BCryptPasswordEncoderAdapter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * La politica de contrasenas: longitud minima y rechazo de las mas usadas.
 */
class PasswordPolicyTest {

    private final PasswordPolicy policy = new PasswordPolicy(14);

    @Test
    @DisplayName("Una contrasena por debajo del minimo se rechaza")
    void unaContrasenaPorDebajoDelMinimoSeRechaza() {
        assertTrue(policy.reject("Corta1!").isPresent(),
                "Una contrasena de 7 caracteres no puede aceptarse");
        assertTrue(policy.reject("1234567890123").isPresent(),
                "Una contrasena de 13 caracteres no puede aceptarse con un minimo de 14");
    }

    @Test
    @DisplayName("Una contrasena de la lista de las mas usadas se rechaza")
    void unaContrasenaDeLaListaSeRechaza() {
        // La lista protege a las implantaciones que bajan el minimo: con el
        // minimo por defecto, esas contrasenas ya se rechazarian por cortas.
        PasswordPolicy conMinimoBajo = new PasswordPolicy(8);

        assertTrue(conMinimoBajo.reject("password").isPresent(),
                "Una contrasena habitual no puede aceptarse por larga que sea");
        assertTrue(conMinimoBajo.reject("1234567890").isPresent(),
                "Una contrasena habitual no puede aceptarse por larga que sea");
        assertTrue(conMinimoBajo.reject("qwerty").isPresent(),
                "Una contrasena habitual no puede aceptarse por larga que sea");
    }

    @Test
    @DisplayName("Una contrasena larga que no esta en la lista se acepta")
    void unaContrasenaLargaQueNoEstaEnLaListaSeAcepta() {
        assertFalse(policy.reject("C0rrec1n-muy-larga-y-propia").isPresent(),
                "Una contrasena larga y propia debe aceptarse");
    }

    @Test
    @DisplayName("La longitud minima es parametrizable")
    void laLongitudMinimaEsParametrizable() {
        PasswordPolicy corta = new PasswordPolicy(8);

        assertEquals(8, corta.minLength());
        assertTrue(corta.reject("Corta1!").isPresent(),
                "Con un minimo de 8, una contrasena de 7 caracteres sigue sin aceptarse");
        assertFalse(corta.reject("Corta12!").isPresent(),
                "Con un minimo de 8, una contrasena de 8 caracteres debe aceptarse");
        assertTrue(corta.reject("1234567890").isPresent(),
                "La lista de contrasenas habituales se aplica con cualquier minimo");
    }

    @Test
    @DisplayName("El factor de coste de BCrypt es parametrizable")
    void elFactorDeCosteDeBcryptEsParametrizable() {
        // Con un coste alto, el hash de la misma contrasena es distinto: es
        // la senal de que el codificador se ha construido con el factor
        // configurado.
        BCryptPasswordEncoderAdapter barato = new BCryptPasswordEncoderAdapter(4);
        BCryptPasswordEncoderAdapter caro = new BCryptPasswordEncoderAdapter(6);

        assertFalse(barato.encode("ContrasenaLarga1!").equals(caro.encode("ContrasenaLarga1!")),
                "El factor de coste configurado debe aplicarse al construir el codificador");
        assertThrows(IllegalStateException.class, () -> new BCryptPasswordEncoderAdapter(2),
                "Un factor de coste fuera de rango debe rechazarse");
    }
}
