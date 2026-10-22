package com.erp.auth.infrastructure.persistence.repository;

import com.erp.auth.infrastructure.persistence.entity.UserJpaEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.time.Instant;
import java.util.UUID;

@Repository
public interface SpringDataUserRepository extends JpaRepository<UserJpaEntity, UUID> {

    Optional<UserJpaEntity> findByEmailAndTenantId(String email, UUID tenantId);

    Optional<UserJpaEntity> findByIdAndTenantId(UUID id, UUID tenantId);

    boolean existsByEmailAndTenantId(String email, UUID tenantId);

    /**
     * Estado del segundo factor de un usuario.
     *
     * <p>Es una PROYECCION y no la entidad: leer la entidad la adjuntaria al
     * contexto de persistencia, y el guardado posterior construiria otra
     * instancia del mismo identificador, que Hibernate rechazaria.
     */
    @Query("SELECT u.mfaSecretCiphertext AS mfaSecretCiphertext, "
            + "u.mfaLastCodeCounter AS mfaLastCodeCounter, u.version AS version "
            + "FROM UserJpaEntity u WHERE u.id = :id")
    java.util.Optional<UserState> findUserState(@Param("id") UUID id);

    /**
     * Estado de la fila que el modelo de dominio no lleva: el secreto del
     * segundo factor, el contador del ultimo codigo aceptado y la version de
     * concurrencia optimista.
     *
     * <p>Es una PROYECCION y no la entidad: leer la entidad la adjuntaria al
     * contexto de persistencia, y el guardado posterior construiria otra
     * instancia del mismo identificador, que Hibernate rechazaria.
     */
    interface UserState {
        String getMfaSecretCiphertext();

        Long getMfaLastCodeCounter();

        Long getVersion();
    }

    /**
     * Incrementa el contador de intentos fallidos EN LA BASE DE DATOS.
     *
     * <p>El incremento es atomico: dos intentos concurrentes sobre la misma
     * cuenta no pueden partir del mismo valor, de modo que ninguno se pierde.
     * Con un lectura-modificacion-escritura, los dos leian el mismo contador
     * y escribian el mismo incremento, y la cuenta se quedaba sin bloqueo
     * tras muchos intentos.
     *
     * <p>El bloqueo se aplica en la misma sentencia: cuando el contador
     * alcanza el maximo, la cuenta queda bloqueada hasta el instante
     * indicado.
     */
    @Modifying
    @Query("UPDATE UserJpaEntity u SET u.failedAttempts = u.failedAttempts + 1, "
            + "u.lockedUntil = CASE WHEN u.failedAttempts + 1 >= :maxAttempts THEN :lockedUntil ELSE u.lockedUntil END "
            + "WHERE u.id = :id")
    int incrementFailedAttempts(@Param("id") UUID id,
                                @Param("maxAttempts") int maxAttempts,
                                @Param("lockedUntil") Instant lockedUntil);

    List<UserJpaEntity> findAllByTenantId(UUID tenantId);
}
