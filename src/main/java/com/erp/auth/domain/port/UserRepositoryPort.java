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
     * Atomically increments the failed login attempt counter and locks the account
     * once the configured threshold is reached.
     *
     * <p>The increment is executed directly in the database rather than via
     * read-modify-write, ensuring concurrent login attempts do not overwrite
     * each other's increments.
     */
    void incrementFailedAttempts(UUID id, int maxAttempts, java.time.Duration lockDuration);
    List<User> findAllByTenantId(TenantId tenantId);
    void deleteById(UUID id);
}
