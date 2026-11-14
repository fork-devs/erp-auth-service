package com.erp.auth.infrastructure.security.mfa;

import com.erp.auth.domain.port.SecondFactorPort;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Time-based one-time password (TOTP) verification adapter.
 *
 * <p>Supports a time window tolerance of one interval (+/- 30 seconds) around the current time
 * to accommodate client clock drift while preventing excessive replay opportunities.
 *
 * <p>Validates expected codes for the previous, current, and next time steps.
 */
@Component
public class TotpSecondFactorAdapter implements SecondFactorPort {

    /** Number of tolerance intervals on either side of the current time step. */
    private static final int WINDOW_TOLERANCE = 1;

    /** Duration of a single TOTP time step, in milliseconds. */
    private static final long INTERVAL_MILLIS = 30_000L;

    private static final String ISSUER = "DriveOS";

    private static final Pattern SIX_DIGIT_PATTERN = Pattern.compile("^[0-9]{6}$");

    private final GoogleAuthenticator authenticator = new GoogleAuthenticator();
    private final SecureRandom secureRandom = new SecureRandom();

    @Override
    public SecondFactorSecret enroll(String accountEmail) {
        try {
            GoogleAuthenticatorKey key = authenticator.createCredentials();
            String account = (accountEmail != null && !accountEmail.isBlank())
                    ? accountEmail.trim()
                    : "user@driveos.pe";
            // Use the standard otpauth:// URI supported by authenticator apps
            // Issuer must be consistent product brand ("DriveOS"), account must be user email, never the secret
            String uri = GoogleAuthenticatorQRGenerator.getOtpAuthTotpURL(ISSUER, account, key);
            return new SecondFactorSecret(key.getKey(), uri);
        } catch (Exception e) {
            throw new IllegalStateException("No se pudo generar el secreto del segundo factor", e);
        }
    }

    @Override
    public SecondFactorSecret enroll() {
        return enroll("user@driveos.pe");
    }

    @Override
    public Optional<Long> verify(String secret, String code, Instant at) {
        if (at == null || secret == null || secret.isBlank() || code == null || code.isBlank()) {
            return Optional.empty();
        }

        String trimmed = code.trim();
        if (!SIX_DIGIT_PATTERN.matcher(trimmed).matches()) {
            return Optional.empty();
        }

        int introducido;
        try {
            introducido = Integer.parseInt(trimmed);
        } catch (NumberFormatException e) {
            return Optional.empty();
        }

        long instante = at.toEpochMilli();
        long intervaloActual = instante / INTERVAL_MILLIS;

        for (int delta = -WINDOW_TOLERANCE; delta <= WINDOW_TOLERANCE; delta++) {
            long contador = intervaloActual + delta;
            long instanteIntervalo = contador * INTERVAL_MILLIS;
            try {
                if (authenticator.getTotpPassword(secret, instanteIntervalo) == introducido) {
                    return Optional.of(contador);
                }
            } catch (Exception e) {
                // Do NOT abort the entire tolerance loop on a single transient error; continue evaluating other windows
                continue;
            }
        }
        return Optional.empty();
    }

    /**
     * Generates a random single-use recovery code.
     * Uses Byte.toUnsignedInt to avoid negative byte sign extension in hexadecimal formatting.
     *
     * @return formatted recovery code string (e.g. XXXXXXXXXX-XXXXXXXXXX)
     */
    public String generarCodigoDeRecuperacion() {
        byte[] bytes = new byte[10];
        secureRandom.nextBytes(bytes);

        StringBuilder codigo = new StringBuilder(24);
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0 && i % 5 == 0) {
                codigo.append('-');
            }
            codigo.append(String.format("%02X", Byte.toUnsignedInt(bytes[i])));
        }
        return codigo.toString();
    }
}
