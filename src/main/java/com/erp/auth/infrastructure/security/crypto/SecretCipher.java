package com.erp.auth.infrastructure.security.crypto;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Cifrado del secreto del segundo factor.
 *
 * <p>Un secreto TOTP se verifica a partir del material compartido: quien lo
 * lea puede generar codigos validos. Guardarlo en claro en la tabla seria
 * guardar una credencial mas, con la diferencia de que no caduca.
 *
 * <p>Se usa AES-GCM: cada cifrado usa un vector de inicializacion distinto,
 * de modo que el mismo secreto no produce el mismo texto cifrado dos veces, y
 * el texto alteration lo invalida.
 *
 * <p>La clave viene de la configuracion. Si no esta, el arranque falla: sin
 * ella, el secreto se guardaria sin cifrar de hecho.
 */
@Component
public class SecretCipher {

    private static final String TRANSFORM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_BITS = 128;
    private static final int IV_LENGTH = 12;
    private static final int KEY_LENGTH_BYTES = 32;

    private final SecretKeySpec key;
    private final SecureRandom secureRandom = new SecureRandom();

    public SecretCipher(@Value("${erp.security.mfa.encryption-key:}") String base64Key) {
        if (base64Key == null || base64Key.isBlank()) {
            throw new IllegalStateException(
                    "No hay clave de cifrado para el secreto del segundo factor. Defina "
                    + "erp.security.mfa.encryption-key con una clave de 32 bytes en Base64. Sin ella, el "
                    + "secreto se guardaria sin cifrar.");
        }

        byte[] bytes;
        try {
            bytes = Base64.getDecoder().decode(base64Key.trim());
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(
                    "La clave de cifrado del segundo factor no es un Base64 valido.", e);
        }
        if (bytes.length != KEY_LENGTH_BYTES) {
            throw new IllegalStateException(
                    "La clave de cifrado del segundo factor debe tener 32 bytes, y la configurada tiene "
                    + bytes.length + ".");
        }
        this.key = new SecretKeySpec(bytes, "AES");
    }

    public String encrypt(String plaintext) {
        if (plaintext == null) {
            return null;
        }
        try {
            byte[] iv = new byte[IV_LENGTH];
            secureRandom.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(TRANSFORM);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] cifrado = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            byte[] resultado = new byte[iv.length + cifrado.length];
            System.arraycopy(iv, 0, resultado, 0, iv.length);
            System.arraycopy(cifrado, 0, resultado, iv.length, cifrado.length);
            return Base64.getEncoder().encodeToString(resultado);
        } catch (Exception e) {
            throw new IllegalStateException("No se pudo cifrar el secreto", e);
        }
    }

    public String decrypt(String ciphertext) {
        if (ciphertext == null) {
            return null;
        }
        try {
            byte[] datos = Base64.getDecoder().decode(ciphertext);
            byte[] iv = new byte[IV_LENGTH];
            byte[] cifrado = new byte[datos.length - IV_LENGTH];
            System.arraycopy(datos, 0, iv, 0, IV_LENGTH);
            System.arraycopy(datos, IV_LENGTH, cifrado, 0, cifrado.length);

            Cipher cipher = Cipher.getInstance(TRANSFORM);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
            return new String(cipher.doFinal(cifrado), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalStateException("No se pudo descifrar el secreto", e);
        }
    }
}
