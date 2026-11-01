package com.erp.auth.infrastructure.persistence.adapter;

import com.erp.auth.domain.model.OtpVerification;
import com.erp.auth.domain.port.OtpVerificationRepositoryPort;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.infrastructure.persistence.TransactionGuard;
import com.erp.auth.infrastructure.persistence.entity.OtpVerificationJpaEntity;
import com.erp.auth.infrastructure.persistence.mapper.OtpVerificationPersistenceMapper;
import com.erp.auth.infrastructure.persistence.repository.SpringDataOtpVerificationRepository;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Component
public class OtpVerificationPersistenceAdapter implements OtpVerificationRepositoryPort {

    private final SpringDataOtpVerificationRepository repository;
    private final TransactionGuard transactionGuard;

    public OtpVerificationPersistenceAdapter(SpringDataOtpVerificationRepository repository,
                                            TransactionGuard transactionGuard) {
        this.repository = repository;
        this.transactionGuard = transactionGuard;
    }

    @Override
    public OtpVerification save(OtpVerification otpVerification) {
        transactionGuard.requireActiveTransaction("saveOtpVerification");
        OtpVerificationJpaEntity entity = OtpVerificationPersistenceMapper.toEntity(otpVerification);
        OtpVerificationJpaEntity saved = repository.save(entity);
        return OtpVerificationPersistenceMapper.toDomain(saved);
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<OtpVerification> findLatestByEmail(Email email) {
        return repository.findLatestByEmail(email.getValue())
                .map(OtpVerificationPersistenceMapper::toDomain);
    }
}
