package com.erp.auth.infrastructure.security.mfa;

import com.erp.auth.domain.port.SecondFactorPort;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * La verificacion del segundo factor.
 *
 * <p>Un codigo se acepta dentro de su intervalo y en el siguiente, para que
 * un reloj de usuario desajustado no impida entrar. Fuera de esa ventana se
 * rechaza: una tolerancia amplia permitiria que un codigo capturado se
 * usara varias veces.
 */
class TotpSecondFactorAdapterTest {

    private static final long INTERVAL_MILLIS = 30_000L;

    private TotpSecondFactorAdapter adapter;
    private GoogleAuthenticator reference;
    private String secret;

    @BeforeEach
    void setUp() {
        adapter = new TotpSecondFactorAdapter();
        reference = new GoogleAuthenticator();
        secret = adapter.enroll().secret();
    }

    @Test
    @DisplayName("El enrolamiento produce un secreto y un enlace de enrolamiento")
    void elEnrolamientoProduceSecretoYEnlace() {
        SecondFactorPort.SecondFactorSecret enrolado = adapter.enroll();

        assertNotNull(enrolado.secret());
        assertFalse(enrolado.secret().isBlank());
        assertNotNull(enrolado.uri());
        assertTrue(enrolado.uri().startsWith("otpauth://"),
                "El enlace debe ser el que entiende la aplicacion autenticadora: " + enrolado.uri());
    }

    @Test
    @DisplayName("El codigo del intervalo actual se acepta")
    void elCodigoDelIntervaloActualSeAcepta() {
        Instant instante = Instant.ofEpochSecond(1_700_000_000L);
        String codigo = codigoEn(instante);

        assertTrue(adapter.verify(secret, codigo, instante).isPresent());
    }

    @Test
    @DisplayName("El mismo codigo se rechaza en el intervalo siguiente, fuera de la ventana")
    void elMismoCodigoSeRechazaFueraDeLaVentana() {
        Instant instante = Instant.ofEpochSecond(1_700_000_000L);
        String codigo = codigoEn(instante);

        // Dos intervalos despues, el codigo ya no vale.
        Instant dosIntervalosDespues = instante.plusMillis(2 * INTERVAL_MILLIS);

        assertFalse(adapter.verify(secret, codigo, dosIntervalosDespues).isPresent(),
                "El codigo de un intervalo anterior no puede seguir valiendo");
    }

    @Test
    @DisplayName("El codigo del intervalo siguiente se acepta en su propio intervalo")
    void elCodigoDelIntervaloSiguienteSeAcepta() {
        Instant instante = Instant.ofEpochSecond(1_700_000_000L);
        Instant siguiente = instante.plusMillis(INTERVAL_MILLIS);

        assertTrue(adapter.verify(secret, codigoEn(siguiente), siguiente).isPresent());
    }

    @Test
    @DisplayName("Un codigo con otra forma no se acepta")
    void unCodigoConOtraFormaNoSeAcepta() {
        Instant instante = Instant.ofEpochSecond(1_700_000_000L);

        assertFalse(adapter.verify(secret, "no-es-un-codigo", instante).isPresent());
        assertFalse(adapter.verify(secret, "", instante).isPresent());
        assertFalse(adapter.verify("", "123456", instante).isPresent());
    }

    @Test
    @DisplayName("La verificacion devuelve el contador del intervalo aceptado")
    void laVerificacionDevuelveElContadorDelIntervalo() {
        Instant instante = Instant.ofEpochSecond(1_700_000_000L);
        long intervaloEsperado = instante.toEpochMilli() / INTERVAL_MILLIS;

        assertEquals(intervaloEsperado, adapter.verify(secret, codigoEn(instante), instante).orElseThrow());
    }

    @Test
    @DisplayName("El codigo de recuperacion tiene el formato esperado")
    void elCodigoDeRecuperacionTieneElFormatoEsperado() {
        String codigo = adapter.generarCodigoDeRecuperacion();

        assertNotNull(codigo);
        assertTrue(codigo.matches("[0-9A-F]{10}-[0-9A-F]{10}"),
                "Formato inesperado: " + codigo);
    }

    private String codigoEn(Instant instante) {
        return String.format("%06d", reference.getTotpPassword(secret, instante.toEpochMilli()));
    }
}
