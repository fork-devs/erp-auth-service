package com.erp.auth.infrastructure.security.mfa;

import com.erp.auth.domain.port.SecondFactorPort;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Infrastructure - TotpSecondFactorAdapter Hardening Test")
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
    @DisplayName("El enrolamiento produce secreto y URI con issuer DriveOS y cuenta de usuario (sin filtrar el secreto en label)")
    void elEnrolamientoProduceSecretoYEnlaceSeguro() {
        String email = "asesor@taller.pe";
        SecondFactorPort.SecondFactorSecret enrolado = adapter.enroll(email);

        assertNotNull(enrolado.secret());
        assertFalse(enrolado.secret().isBlank());
        assertNotNull(enrolado.uri());
        assertTrue(enrolado.uri().startsWith("otpauth://totp/"));
        assertTrue(enrolado.uri().contains("issuer=DriveOS") || enrolado.uri().contains("DriveOS"));
        assertTrue(enrolado.uri().contains(email), "La cuenta debe ser el correo del usuario: " + enrolado.uri());
        // El secreto NO debe ser el account o label
        assertFalse(enrolado.uri().startsWith("otpauth://totp/" + enrolado.secret()),
                "El secreto no debe ser la etiqueta de cuenta en el QR: " + enrolado.uri());
    }

    @Test
    @DisplayName("El codigo del intervalo actual se acepta")
    void elCodigoDelIntervaloActualSeAcepta() {
        Instant instante = Instant.ofEpochSecond(1_700_000_000L);
        String codigo = codigoEn(instante);

        assertTrue(adapter.verify(secret, codigo, instante).isPresent());
    }

    @Test
    @DisplayName("El mismo codigo se rechaza fuera de la ventana de tolerancia (+/- 1)")
    void elMismoCodigoSeRechazaFueraDeLaVentana() {
        Instant instante = Instant.ofEpochSecond(1_700_000_000L);
        String codigo = codigoEn(instante);

        Instant dosIntervalosDespues = instante.plusMillis(2 * INTERVAL_MILLIS);
        assertFalse(adapter.verify(secret, codigo, dosIntervalosDespues).isPresent());
    }

    @Test
    @DisplayName("El codigo del intervalo siguiente se acepta en su propio intervalo")
    void elCodigoDelIntervaloSiguienteSeAcepta() {
        Instant instante = Instant.ofEpochSecond(1_700_000_000L);
        Instant siguiente = instante.plusMillis(INTERVAL_MILLIS);

        assertTrue(adapter.verify(secret, codigoEn(siguiente), siguiente).isPresent());
    }

    @Test
    @DisplayName("Codigos con longitud distinta a 6 digitos (7 digitos o 3 digitos) se rechazan")
    void codigosConLongitudInvalidaSeRechazan() {
        Instant instante = Instant.ofEpochSecond(1_700_000_000L);

        assertFalse(adapter.verify(secret, "0123456", instante).isPresent(), "7 digitos deben rechazarse");
        assertFalse(adapter.verify(secret, "12345", instante).isPresent(), "5 digitos deben rechazarse");
        assertFalse(adapter.verify(secret, "+12345", instante).isPresent(), "Signos deben rechazarse");
        assertFalse(adapter.verify(secret, "no-es", instante).isPresent());
        assertFalse(adapter.verify(secret, "", instante).isPresent());
        assertFalse(adapter.verify("", "123456", instante).isPresent());
    }

    @Test
    @DisplayName("verify con instante null retorna empty sin arrojar NullPointerException")
    void verifyConInstantNullRetornaEmpty() {
        assertFalse(adapter.verify(secret, "123456", null).isPresent());
    }

    @Test
    @DisplayName("La verificacion devuelve el contador del intervalo aceptado")
    void laVerificacionDevuelveElContadorDelIntervalo() {
        Instant instante = Instant.ofEpochSecond(1_700_000_000L);
        long intervaloEsperado = instante.toEpochMilli() / INTERVAL_MILLIS;

        assertEquals(intervaloEsperado, adapter.verify(secret, codigoEn(instante), instante).orElseThrow());
    }

    @Test
    @DisplayName("El codigo de recuperacion tiene exactamente 10 hex - 10 hex (21 caracteres) y maneja bytes negativos")
    void elCodigoDeRecuperacionTieneElFormatoEsperado() {
        for (int i = 0; i < 50; i++) {
            String codigo = adapter.generarCodigoDeRecuperacion();

            assertNotNull(codigo);
            assertEquals(21, codigo.length(), "Debe tener longitud exacta de 21 caracteres: " + codigo);
            assertTrue(codigo.matches("^[0-9A-F]{10}-[0-9A-F]{10}$"),
                    "Formato de 10 hex y 10 hex: " + codigo);
        }
    }

    private String codigoEn(Instant instante) {
        return String.format("%06d", reference.getTotpPassword(secret, instante.toEpochMilli()));
    }
}
