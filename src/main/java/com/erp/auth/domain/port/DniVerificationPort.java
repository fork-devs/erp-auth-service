package com.erp.auth.domain.port;

/**
 * Port for verifying national identity numbers (DNI) against the integration hub before persisting public registrations.
 */
public interface DniVerificationPort {

    DniVerificationResult verifyDni(String dni);

    record DniVerificationResult(String documentNumber, String fullName, boolean valid) {
        public static DniVerificationResult invalid(String dni) {
            return new DniVerificationResult(dni, null, false);
        }
    }
}
