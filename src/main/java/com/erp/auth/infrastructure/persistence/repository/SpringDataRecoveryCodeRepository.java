package com.erp.auth.infrastructure.persistence.repository;

import com.erp.auth.infrastructure.persistence.entity.RecoveryCodeJpaEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface SpringDataRecoveryCodeRepository extends JpaRepository<RecoveryCodeJpaEntity, UUID> {

    Optional<RecoveryCodeJpaEntity> findByUserIdAndCodeHash(UUID userId, String codeHash);

    /**
     * Marks the recovery code as used ONLY if currently unused.
     * Enforced within the atomic query condition to ensure concurrent requests
     * cannot double-spend the same recovery code.
     */
    @Modifying
    @Query("UPDATE RecoveryCodeJpaEntity r SET r.usedAt = :now "
            + "WHERE r.userId = :userId AND r.codeHash = :codeHash AND r.usedAt IS NULL AND r.expiresAt > :now")
    int markUsedIfNotUsed(@Param("userId") UUID userId,
                          @Param("codeHash") String codeHash,
                          @Param("now") Instant now);

    @Modifying
    @Query("DELETE FROM RecoveryCodeJpaEntity r WHERE r.expiresAt < :now")
    int deleteExpired(@Param("now") Instant now);
}
