package com.erp.auth.infrastructure.security.mfa;

import com.erp.auth.domain.port.SecondFactorPort;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.time.Instant;

/**
 * Verificacion de codigos de un solo uso temporizados (TOTP).
 *
 * <p>Se admite una ventana de un intervalo a cada lado del instante actual:
 * un reloj de usuario desajustado por unos segundos no debe impedir entrar,
 * pero la tolerancia es de UN intervalo, no mas: una ventana amplia permitiria
 * que un codigo capturado se usara varias veces.
 *
 * <p>La biblioteca calcula el codigo de un instante, pero no la ventana de
 * tolerancia, de modo que esta se implementa aqui: se comparan los codigos
 * esperados de los intervalos anterior, actual y siguiente.
 */
@Component
public class TotpSecondFactorAdapter implements SecondFactorPort {

    /** Numero de intervalos de tolerancia a cada lado del instante actual. */
    private static final int WINDOW_TOLERANCE = 1;

    /** Duracion de un intervalo, en milisegundos. */
    private static final long INTERVAL_MILLIS = 30_000L;

    private static final String ISSUER = "DriveOS";

    private final GoogleAuthenticator authenticator = new GoogleAuthenticator();
    private final SecureRandom secureRandom = new SecureRandom();

    @Override
    public SecondFactorSecret enroll() {
        try {
            GoogleAuthenticatorKey key = authenticator.createCredentials();
            // El enlace otpauth:// es el que entiende la aplicacion
            // autenticadora. El otro metodo de la biblioteca devuelve la URL
            // de una imagen de codigo QR, que es otra cosa.
            String uri = GoogleAuthenticatorQRGenerator.getOtpAuthTotpURL(key.getKey(), ISSUER, key);
            return new SecondFactorSecret(key.getKey(), uri);
        } catch (Exception e) {
            throw new IllegalStateException("No se pudo generar el secreto del segundo factor", e);
        }
    }

    @Override
    public boolean verify(String secret, String code, Instant at) {
        if (secret == null || secret.isBlank() || code == null || code.isBlank()) {
            return false;
        }

        int introducido;
        try {
            introducido = Integer.parseInt(code.trim());
        } catch (NumberFormatException e) {
            return false;
        }

        long instante = at.toEpochMilli();
        long intervaloActual = instante / INTERVAL_MILLIS;

        for (int delta = -WINDOW_TOLERANCE; delta <= WINDOW_TOLERANCE; delta++) {
            long instanteIntervalo = (intervaloActual + delta) * INTERVAL_MILLIS;
            try {
                if (authenticator.getTotpPassword(secret, instanteIntervalo) == introducido) {
                    return true;
                }
            } catch (Exception e) {
                return false;
            }
        }
        return false;
    }

    /**
     * Genera un codigo de recuperacion de un solo uso.
     */
    public String generarCodigoDeRecuperacion() {
        byte[] bytes = new byte[10];
        secureRandom.nextBytes(bytes);

        StringBuilder codigo = new StringBuilder(24);
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0 && i % 5 == 0) {
                codigo.append('-');
            }
            codigo.append(String.format("%02X", bytes[i]));
        }
        return codigo.toString();
    }
}
