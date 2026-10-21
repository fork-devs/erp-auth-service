package com.erp.auth.domain.port;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Persistencia del segundo factor: el secreto enrolado y los codigos de
 * recuperacion.
 *
 * <p>El secreto viaja CIFRADO por el puerto: la capa de aplicacion no sabe
 * como se cifra, y el repositorio no lo descifra. Quien lo guarda es el
 * que sabe encriptarlo.
 */
public interface SecondFactorRepositoryPort {

    /**
     * Guarda el secreto enrolado, ya cifrado.
     */
    void storeSecret(UUID userId, String encryptedSecret);

    /**
     * Secreto enrolado, cifrado. Vacio si el usuario no ha enrolado el
     * segundo factor.
     */
    Optional<String> findSecret(UUID userId);

    /**
     * Guarda los codigos de recuperacion, hasheados. Un codigo de
     * recuperacion es una credencial: se guarda su hash, nunca el valor.
     */
    void storeRecoveryCodes(UUID userId, List<String> hashedCodes, Instant expiresAt);

    /**
     * Consume un codigo de recuperacion: lo marca como usado en el mismo
     * momento, de modo que no pueda usarse dos veces.
     *
     * @return el codigo consumido, si existia y no habia sido usado
     */
    Optional<RecoveryCode> consumeRecoveryCode(UUID userId, String hashedCode);

    /**
     * Contador del ultimo codigo aceptado por el usuario. Vacio si todavia
     * no ha aceptado ninguno.
     */
    Optional<Long> findLastAcceptedCounter(UUID userId);

    /**
     * Registra el contador del codigo que acaba de aceptarse, de modo que el
     * mismo codigo no pueda usarse otra vez.
     */
    void recordAcceptedCounter(UUID userId, long counter);

    /**
     * Un codigo de recuperacion consumido.
     */
    record RecoveryCode(UUID id, Instant expiresAt) {
    }
}
