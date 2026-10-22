package com.erp.auth.domain.port;

import com.erp.auth.domain.model.User;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.domain.valueobject.TenantId;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface UserRepositoryPort {
    User save(User user);
    Optional<User> findByIdAndTenantId(UUID id, TenantId tenantId);
    Optional<User> findByEmailAndTenantId(Email email, TenantId tenantId);
    boolean existsByEmailAndTenantId(Email email, TenantId tenantId);

    /**
     * Incrementa el contador de intentos fallidos de forma ATOMICA, y bloquea
     * la cuenta cuando el contador alcanza el maximo.
     *
     * <p>El incremento se hace en la base de datos, no con una
     * lectura-modificacion-escritura: dos intentos concurrentes sobre la misma
     * cuenta no pueden partir del mismo valor, de modo que ninguno se pierde.
     */
    void incrementFailedAttempts(UUID id, int maxAttempts, java.time.Duration lockDuration);
    List<User> findAllByTenantId(TenantId tenantId);
    void deleteById(UUID id);
}
