package com.erp.auth.infrastructure.persistence.adapter;

import com.erp.auth.domain.model.OtpVerification;
import com.erp.auth.domain.port.OtpVerificationRepositoryPort;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.domain.valueobject.OtpVerificationId;
import com.erp.auth.infrastructure.persistence.TransactionGuard;
import com.erp.auth.infrastructure.persistence.entity.OtpVerificationJpaEntity;
import com.erp.auth.infrastructure.persistence.mapper.OtpVerificationPersistenceMapper;
import com.erp.auth.infrastructure.persistence.repository.SpringDataOtpVerificationRepository;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Propagation;
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
    @Transactional(propagation = Propagation.MANDATORY)
    public OtpVerification save(OtpVerification otpVerification) {
        transactionGuard.requireActiveTransaction("saveOtpVerification");
        OtpVerificationJpaEntity entity = OtpVerificationPersistenceMapper.toEntity(otpVerification);
        OtpVerificationJpaEntity saved = repository.save(entity);
        return OtpVerificationPersistenceMapper.toDomain(saved);
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<OtpVerification> findLatestByEmail(Email email) {
        return repository.findLatestByEmail(email.value())
                .map(OtpVerificationPersistenceMapper::toDomain);
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<OtpVerification> findById(OtpVerificationId id) {
        return repository.findById(id.value())
                .map(OtpVerificationPersistenceMapper::toDomain);
    }

    @Override
    @Transactional(propagation = Propagation.MANDATORY)
    public void incrementAttempts(OtpVerificationId id) {
        transactionGuard.requireActiveTransaction("incrementAttempts");
        repository.incrementAttempts(id.value());
    }

    @Override
    @Transactional(propagation = Propagation.MANDATORY)
    public void invalidateAllPendingByEmail(Email email) {
        transactionGuard.requireActiveTransaction("invalidateAllPendingByEmail");
        repository.invalidateAllPendingByEmail(email.value());
    }
}
