package com.erp.auth.infrastructure.persistence.adapter;

import com.erp.auth.domain.model.UserInvitation;
import com.erp.auth.domain.port.UserInvitationRepositoryPort;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.infrastructure.persistence.TransactionGuard;
import com.erp.auth.infrastructure.persistence.entity.UserInvitationJpaEntity;
import com.erp.auth.infrastructure.persistence.mapper.UserInvitationPersistenceMapper;
import com.erp.auth.infrastructure.persistence.repository.SpringDataUserInvitationRepository;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Component
public class UserInvitationPersistenceAdapter implements UserInvitationRepositoryPort {

    private final SpringDataUserInvitationRepository repository;
    private final TransactionGuard transactionGuard;

    public UserInvitationPersistenceAdapter(SpringDataUserInvitationRepository repository,
                                            TransactionGuard transactionGuard) {
        this.repository = repository;
        this.transactionGuard = transactionGuard;
    }

    @Override
    public UserInvitation save(UserInvitation invitation) {
        transactionGuard.requireActiveTransaction("saveUserInvitation");
        UserInvitationJpaEntity entity = UserInvitationPersistenceMapper.toEntity(invitation);
        UserInvitationJpaEntity saved = repository.save(entity);
        return UserInvitationPersistenceMapper.toDomain(saved);
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<UserInvitation> findById(UUID id) {
        return repository.findById(id).map(UserInvitationPersistenceMapper::toDomain);
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<UserInvitation> findByTokenHash(String tokenHash) {
        return repository.findByTokenHash(tokenHash).map(UserInvitationPersistenceMapper::toDomain);
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<UserInvitation> findLatestByEmailAndTenantId(Email email, UUID tenantId) {
        return repository.findFirstByEmailAndTenantIdOrderByCreatedAtDesc(email.getValue(), tenantId)
                .map(UserInvitationPersistenceMapper::toDomain);
    }

    @Override
    public void invalidateAllByEmailAndTenantId(Email email, UUID tenantId) {
        transactionGuard.requireActiveTransaction("invalidateAllUserInvitations");
        repository.invalidateAllByEmailAndTenantId(email.getValue(), tenantId, Instant.now());
    }
}
