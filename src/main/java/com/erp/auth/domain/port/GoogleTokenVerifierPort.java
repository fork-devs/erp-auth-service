package com.erp.auth.domain.port;

import com.erp.auth.domain.model.GoogleTokenPayload;

public interface GoogleTokenVerifierPort {
    GoogleTokenPayload verifyToken(String idToken);
}
