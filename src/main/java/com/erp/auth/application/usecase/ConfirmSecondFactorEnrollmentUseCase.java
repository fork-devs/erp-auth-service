package com.erp.auth.application.usecase;

import java.util.UUID;

/**
 * Confirmacion del enrolamiento del segundo factor.
 *
 * <p>El enrolamiento no se completa hasta que el usuario demuestra que ha
 * enlazado su aplicacion autenticadora, con un codigo valido.
 */
public interface ConfirmSecondFactorEnrollmentUseCase {

    /**
     * @throws com.erp.auth.domain.exception.InvalidSecondFactorCodeException
     *         si el codigo no es valido
     */
    void confirm(UUID userId, UUID tenantId, String code);
}
