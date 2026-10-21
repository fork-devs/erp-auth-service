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

    private final SpringDataUserRepository springDataUserRepository;
    private final SpringDataRoleRepository springDataRoleRepository;

    public UserPersistenceAdapter(SpringDataUserRepository springDataUserRepository,
                                   SpringDataRoleRepository springDataRoleRepository) {
        this.springDataUserRepository = springDataUserRepository;
        this.springDataRoleRepository = springDataRoleRepository;
    }

    @Override
    @Transactional
    public User save(User user) {
        UserJpaEntity entity = UserPersistenceMapper.toEntity(user, resolveManagedRoles(user));
        UserJpaEntity savedEntity = springDataUserRepository.save(entity);
        return UserPersistenceMapper.toDomain(savedEntity);
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
    @Transactional
    public void deleteById(UUID id) {
        springDataUserRepository.deleteById(id);
    }

    /**
     * Los roles del dominio se resuelven contra el catalogo dentro de la misma
     * transaccion, de modo que la asignacion referencie la fila real y no una
     * copia desatendida.
     */
    private Set<RoleJpaEntity> resolveManagedRoles(User user) {
        if (user.getRoles() == null || user.getRoles().isEmpty()) {
            return Set.of();
        }
        List<UUID> roleIds = user.getRoles().stream().map(Role::getId).toList();
        return new HashSet<>(springDataRoleRepository.findAllById(roleIds));
    }
}
