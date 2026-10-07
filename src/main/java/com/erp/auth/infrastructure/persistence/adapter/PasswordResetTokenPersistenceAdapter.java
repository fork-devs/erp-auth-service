package com.erp.auth.infrastructure.persistence.adapter;

import com.erp.auth.domain.model.PasswordResetToken;
import com.erp.auth.domain.port.PasswordResetTokenRepositoryPort;
import com.erp.auth.infrastructure.persistence.entity.PasswordResetTokenJpaEntity;
import com.erp.auth.infrastructure.persistence.mapper.PasswordResetTokenPersistenceMapper;
import com.erp.auth.infrastructure.persistence.repository.SpringDataPasswordResetTokenRepository;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.UUID;

@Component
public class PasswordResetTokenPersistenceAdapter implements PasswordResetTokenRepositoryPort {

    private final SpringDataPasswordResetTokenRepository repository;

    public PasswordResetTokenPersistenceAdapter(SpringDataPasswordResetTokenRepository repository) {
        this.repository = repository;
    }

    @Override
    @Transactional
    public PasswordResetToken save(PasswordResetToken token) {
        PasswordResetTokenJpaEntity entity = PasswordResetTokenPersistenceMapper.toEntity(token);
        PasswordResetTokenJpaEntity saved = repository.save(entity);
        return PasswordResetTokenPersistenceMapper.toDomain(saved);
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<PasswordResetToken> findByTokenHash(String tokenHash) {
        return repository.findByTokenHash(tokenHash)
                .map(PasswordResetTokenPersistenceMapper::toDomain);
    }

    @Override
    @Transactional
    public void invalidateAllByUserId(UUID userId) {
        repository.invalidateAllByUserId(userId, java.time.Instant.now());
    }
}
