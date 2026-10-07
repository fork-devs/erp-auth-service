package com.erp.auth.infrastructure.persistence.adapter;

import com.erp.auth.domain.model.User;
import com.erp.auth.domain.port.UserRepositoryPort;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.domain.valueobject.TenantId;
import com.erp.auth.infrastructure.persistence.entity.UserJpaEntity;
import com.erp.auth.infrastructure.persistence.mapper.UserPersistenceMapper;
import com.erp.auth.infrastructure.persistence.repository.SpringDataUserRepository;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

@Component
public class UserPersistenceAdapter implements UserRepositoryPort {

    private final SpringDataUserRepository springDataUserRepository;

    public UserPersistenceAdapter(SpringDataUserRepository springDataUserRepository) {
        this.springDataUserRepository = springDataUserRepository;
    }

    @Override
    @Transactional
    public User save(User user) {
        UserJpaEntity entity = UserPersistenceMapper.toEntity(user);
        UserJpaEntity savedEntity = springDataUserRepository.save(entity);
        return UserPersistenceMapper.toDomain(savedEntity);
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<User> findById(UUID id) {
        return springDataUserRepository.findById(id)
                .map(UserPersistenceMapper::toDomain);
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<User> findByEmail(Email email) {
        return springDataUserRepository.findByEmail(email.getValue())
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
    public boolean existsByEmail(Email email) {
        return springDataUserRepository.existsByEmail(email.getValue());
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
}
