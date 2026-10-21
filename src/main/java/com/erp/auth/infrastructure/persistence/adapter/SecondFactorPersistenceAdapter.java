package com.erp.auth.infrastructure.persistence.adapter;

import com.erp.auth.domain.port.SecondFactorRepositoryPort;
import com.erp.auth.infrastructure.persistence.entity.RecoveryCodeJpaEntity;
import com.erp.auth.infrastructure.persistence.entity.UserJpaEntity;
import com.erp.auth.infrastructure.persistence.repository.SpringDataRecoveryCodeRepository;
import com.erp.auth.infrastructure.persistence.repository.SpringDataUserRepository;
import com.erp.auth.infrastructure.persistence.TransactionGuard;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Component
public class SecondFactorPersistenceAdapter implements SecondFactorRepositoryPort {

    private final TransactionGuard transactionGuard;
    private final SpringDataUserRepository userRepository;
    private final SpringDataRecoveryCodeRepository recoveryCodeRepository;

    public SecondFactorPersistenceAdapter(SpringDataUserRepository userRepository,
                                          SpringDataRecoveryCodeRepository recoveryCodeRepository,
                                          TransactionGuard transactionGuard) {
        this.userRepository = userRepository;
        this.recoveryCodeRepository = recoveryCodeRepository;
        this.transactionGuard = transactionGuard;
    }

    @Override
    public void storeSecret(UUID userId, String encryptedSecret) {
        transactionGuard.requireActiveTransaction("storeSecondFactorSecret");
        UserJpaEntity user = userRepository.findById(userId).orElseThrow(
                () -> new IllegalStateException("El usuario " + userId + " no existe"));
        user.setMfaSecretCiphertext(encryptedSecret);
        userRepository.save(user);
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<String> findSecret(UUID userId) {
        return userRepository.findById(userId).map(UserJpaEntity::getMfaSecretCiphertext);
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<Long> findLastAcceptedCounter(UUID userId) {
        return userRepository.findById(userId).map(UserJpaEntity::getMfaLastCodeCounter);
    }

    @Override
    public void recordAcceptedCounter(UUID userId, long counter) {
        transactionGuard.requireActiveTransaction("recordAcceptedSecondFactorCode");
        UserJpaEntity user = userRepository.findById(userId).orElseThrow(
                () -> new IllegalStateException("El usuario " + userId + " no existe"));
        user.setMfaLastCodeCounter(counter);
        userRepository.save(user);
    }

    @Override
    public void storeRecoveryCodes(UUID userId, List<String> hashedCodes, Instant expiresAt) {
        transactionGuard.requireActiveTransaction("storeRecoveryCodes");
        List<RecoveryCodeJpaEntity> entidades = hashedCodes.stream()
                .map(hash -> new RecoveryCodeJpaEntity(
                        UUID.randomUUID(), userId, hash, null, expiresAt, Instant.now()))
                .toList();
        recoveryCodeRepository.saveAll(entidades);
    }

    @Override
    public Optional<RecoveryCode> consumeRecoveryCode(UUID userId, String hashedCode) {
        transactionGuard.requireActiveTransaction("consumeRecoveryCode");

        Optional<RecoveryCodeJpaEntity> codigo = recoveryCodeRepository
                .findByUserIdAndCodeHash(userId, hashedCode);

        if (codigo.isEmpty()) {
            return Optional.empty();
        }

        int marcadas = recoveryCodeRepository.markUsedIfNotUsed(userId, hashedCode, Instant.now());
        if (marcadas == 0) {
            // El codigo ya se habia usado: un codigo de recuperacion es de un
            // solo uso.
            return Optional.empty();
        }

        return Optional.of(new RecoveryCode(codigo.get().getId(), codigo.get().getExpiresAt()));
    }

    /**
     * Elimina los codigos de recuperacion caducados.
     */
    public int deleteExpiredRecoveryCodes(Instant now) {
        transactionGuard.requireActiveTransaction("deleteExpiredRecoveryCodes");
        return recoveryCodeRepository.deleteExpired(now);
    }
}
