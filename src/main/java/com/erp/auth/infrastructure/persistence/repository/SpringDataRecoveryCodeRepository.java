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
     * Marca el codigo como usado SOLO si no lo estaba. La condicion va en la
     * propia sentencia: dos usos concurrentes del mismo codigo no pueden
     * conseguir que ambos lomarked.
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
