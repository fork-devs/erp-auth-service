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
    List<User> findAllByTenantId(TenantId tenantId);
    void deleteById(UUID id);
}
