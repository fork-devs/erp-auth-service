package com.erp.auth.application.usecase;

import java.util.UUID;

/**
 * Enrolamiento del segundo factor.
 *
 * <p>Genera el secreto y los codigos de recuperacion, y los entrega al
 * usuario por el canal de notificacion. NO se devuelven en la respuesta de la
 * API: devolver el secreto por la API es devolver la credencial a quien la
 * pide.
 */
public interface EnrollSecondFactorUseCase {

    /**
     * Genera el secreto y los codigos de recuperacion, y los entrega al
     * usuario por su direccion de correo.
     *
     * @param userId   el usuario que se enrola
     * @param tenantId el taller al que pertenece
     */
    void enroll(UUID userId, UUID tenantId);
}
