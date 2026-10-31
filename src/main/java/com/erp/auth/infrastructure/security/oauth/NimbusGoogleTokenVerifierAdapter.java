package com.erp.auth.infrastructure.security.oauth;

import com.erp.auth.domain.exception.GoogleAuthenticationException;
import com.erp.auth.domain.model.GoogleTokenPayload;
import com.erp.auth.domain.port.GoogleTokenVerifierPort;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.util.Date;

@Component
public class NimbusGoogleTokenVerifierAdapter implements GoogleTokenVerifierPort {

    @Value("${google.client.id:}")
    private String configuredClientId;

    @Override
    public GoogleTokenPayload verifyToken(String idToken) {
        if (idToken == null || idToken.isBlank()) {
            throw new GoogleAuthenticationException("Google ID token cannot be null or empty");
        }

        try {
            SignedJWT signedJWT = SignedJWT.parse(idToken);
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

            Date expirationTime = claims.getExpirationTime();
            if (expirationTime != null && new Date().after(expirationTime)) {
                throw new GoogleAuthenticationException("Google ID token has expired");
            }

            String email = claims.getStringClaim("email");
            if (email == null || email.isBlank()) {
                throw new GoogleAuthenticationException("Google token does not contain an email claim");
            }

            String name = claims.getStringClaim("name");
            if (name == null || name.isBlank()) {
                name = email.split("@")[0];
            }

            String subject = claims.getSubject();
            if (subject == null || subject.isBlank()) {
                subject = email;
            }

            return new GoogleTokenPayload(email, name, subject);
        } catch (ParseException e) {
            throw new GoogleAuthenticationException("Invalid Google ID token format: " + e.getMessage(), e);
        }
    }
}
