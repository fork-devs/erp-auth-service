package com.erp.auth.infrastructure.persistence.adapter;

import com.erp.auth.domain.model.RefreshToken;
import com.erp.auth.domain.port.RefreshTokenRepositoryPort;
import com.erp.auth.infrastructure.persistence.entity.RefreshTokenJpaEntity;
import com.erp.auth.infrastructure.persistence.mapper.RefreshTokenPersistenceMapper;
import com.erp.auth.infrastructure.persistence.repository.SpringDataRefreshTokenRepository;
import com.erp.auth.infrastructure.persistence.TransactionGuard;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.UUID;

@Component
public class RefreshTokenPersistenceAdapter implements RefreshTokenRepositoryPort {

    private final TransactionGuard transactionGuard;
    private final SpringDataRefreshTokenRepository springDataRefreshTokenRepository;

    public RefreshTokenPersistenceAdapter(SpringDataRefreshTokenRepository springDataRefreshTokenRepository,
                                         TransactionGuard transactionGuard) {
        this.springDataRefreshTokenRepository = springDataRefreshTokenRepository;
        this.transactionGuard = transactionGuard;
    }

    @Override
    public RefreshToken save(RefreshToken refreshToken) {
        transactionGuard.requireActiveTransaction("saveRefreshToken");
        RefreshTokenJpaEntity entity = RefreshTokenPersistenceMapper.toEntity(refreshToken);
        RefreshTokenJpaEntity saved = springDataRefreshTokenRepository.save(entity);
        return RefreshTokenPersistenceMapper.toDomain(saved);
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<RefreshToken> findByTokenHashAndTenantId(String tokenHash, UUID tenantId) {
        return springDataRefreshTokenRepository.findByTokenHashAndTenantId(tokenHash, tenantId)
                .map(RefreshTokenPersistenceMapper::toDomain);
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<RefreshToken> findByTokenHash(String tokenHash) {
        return springDataRefreshTokenRepository.findByTokenHash(tokenHash)
                .map(RefreshTokenPersistenceMapper::toDomain);
    }

    @Override
    public void revokeByTokenHash(String tokenHash) {
        transactionGuard.requireActiveTransaction("revokeByTokenHash");
        springDataRefreshTokenRepository.revokeByTokenHash(tokenHash);
    }

    @Override
    public void revokeAllByUserId(UUID userId) {
        transactionGuard.requireActiveTransaction("revokeAllByUserId");
        springDataRefreshTokenRepository.revokeAllByUserId(userId);
    }
}
