package com.erp.auth.infrastructure.security.crypto;

import com.erp.auth.domain.port.PasswordEncoderPort;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class BCryptPasswordEncoderAdapter implements PasswordEncoderPort {

    private final PasswordEncoder passwordEncoder;

    /**
     * El factor de coste es configurable, con el valor actual (12) como
     * defecto. Un coste alto hace la verificacion lenta, lo que a su vez es
     * la defensa contra la fuerza bruta: conviene poder subirlo sin
     * recompilar.
     */
    public BCryptPasswordEncoderAdapter(
            @Value("${erp.security.password.bcrypt-cost:12}") int bcryptCost) {
        if (bcryptCost < 4 || bcryptCost > 31) {
            throw new IllegalStateException(
                    "El factor de coste de BCrypt debe estar entre 4 y 31, y el configurado es " + bcryptCost + ".");
        }
        this.passwordEncoder = new BCryptPasswordEncoder(bcryptCost);
    }

    @Override
    public String encode(CharSequence rawPassword) {
        return passwordEncoder.encode(rawPassword);
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        return passwordEncoder.matches(rawPassword, encodedPassword);
    }
}
