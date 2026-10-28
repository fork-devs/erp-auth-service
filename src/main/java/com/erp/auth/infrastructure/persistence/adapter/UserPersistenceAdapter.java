package com.erp.auth.infrastructure.persistence.adapter;

import com.erp.auth.domain.model.Role;
import com.erp.auth.domain.model.User;
import com.erp.auth.domain.port.UserRepositoryPort;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.domain.valueobject.PasswordHash;
import com.erp.auth.domain.valueobject.TenantId;
import com.erp.auth.infrastructure.persistence.entity.RoleJpaEntity;
import com.erp.auth.infrastructure.persistence.entity.UserJpaEntity;
import com.erp.auth.infrastructure.persistence.mapper.UserPersistenceMapper;
import com.erp.auth.infrastructure.persistence.repository.SpringDataRoleRepository;
import com.erp.auth.infrastructure.persistence.repository.SpringDataUserRepository;
import com.erp.auth.infrastructure.persistence.TransactionGuard;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Component
public class UserPersistenceAdapter implements UserRepositoryPort {

    private final TransactionGuard transactionGuard;
    private final SpringDataUserRepository springDataUserRepository;
    private final SpringDataRoleRepository springDataRoleRepository;

    public UserPersistenceAdapter(SpringDataUserRepository springDataUserRepository,
                                   SpringDataRoleRepository springDataRoleRepository,
                                   TransactionGuard transactionGuard) {
        this.springDataUserRepository = springDataUserRepository;
        this.springDataRoleRepository = springDataRoleRepository;
        this.transactionGuard = transactionGuard;
    }

    @Override
    public User save(User user) {
        transactionGuard.requireActiveTransaction("saveUser");
        UserJpaEntity entity = UserPersistenceMapper.toEntity(user, resolveManagedRoles(user));
        preservarSegundoFactor(entity);
        UserJpaEntity savedEntity = springDataUserRepository.save(entity);
        return UserPersistenceMapper.toDomain(savedEntity);
    }

    /**
     * Preserves second-factor authentication infrastructure state across entity updates.
     *
     * <p>Encrypted 2FA secrets and the last accepted code counter are infrastructure-level
     * columns not modeled in the core domain aggregate. Preserving them here prevents
     * standard domain save operations (such as password changes, login counters, or name updates)
     * from inadvertently clearing active 2FA credentials.
     */
    private void preservarSegundoFactor(UserJpaEntity entity) {
        springDataUserRepository.findUserState(entity.getId()).ifPresent(estado -> {
            entity.setMfaSecretCiphertext(estado.getMfaSecretCiphertext());
            entity.setMfaLastCodeCounter(estado.getMfaLastCodeCounter());
            // Retain the version attribute so Hibernate performs an UPDATE rather than an INSERT
            entity.setVersion(estado.getVersion());
        });
    }

    @Override
    public void incrementFailedAttempts(UUID id, int maxAttempts, java.time.Duration lockDuration) {
        transactionGuard.requireActiveTransaction("incrementFailedAttempts");
        springDataUserRepository.incrementFailedAttempts(
                id, maxAttempts, java.time.Instant.now().plus(lockDuration));
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<User> findByIdAndTenantId(UUID id, TenantId tenantId) {
        return springDataUserRepository.findByIdAndTenantId(id, tenantId.getValue())
                .map(UserPersistenceMapper::toDomain);
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<User> findByEmailAndTenantId(Email email, TenantId tenantId) {
        return springDataUserRepository.findByEmailAndTenantId(email.getValue(), tenantId.getValue())
                .map(UserPersistenceMapper::toDomain);
    }

    @Override
    @Transactional(readOnly = true)
    public boolean existsByEmailAndTenantId(Email email, TenantId tenantId) {
        return springDataUserRepository.existsByEmailAndTenantId(email.getValue(), tenantId.getValue());
    }

    @Override
    @Transactional(readOnly = true)
    public List<User> findAllByTenantId(TenantId tenantId) {
        return springDataUserRepository.findAllByTenantId(tenantId.getValue()).stream()
                .map(UserPersistenceMapper::toDomain)
                .collect(Collectors.toList());
    }

    @Override
    public void deleteById(UUID id) {
        transactionGuard.requireActiveTransaction("deleteUser");
        springDataUserRepository.deleteById(id);
    }

    /**
     * Resolves domain roles against catalog entities within the current transaction,
     * ensuring assignments reference existing managed rows.
     */
    private Set<RoleJpaEntity> resolveManagedRoles(User user) {
        if (user.getRoles() == null || user.getRoles().isEmpty()) {
            return Set.of();
        }
        List<UUID> roleIds = user.getRoles().stream().map(Role::getId).toList();
        return new HashSet<>(springDataRoleRepository.findAllById(roleIds));
    }
}
