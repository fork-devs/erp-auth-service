package com.erp.auth.infrastructure.persistence.repository;

import com.erp.auth.infrastructure.persistence.entity.RevokedTokenJpaEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.UUID;

@Repository
public interface SpringDataRevokedTokenRepository extends JpaRepository<RevokedTokenJpaEntity, UUID> {

    @Modifying
    @Query("DELETE FROM RevokedTokenJpaEntity r WHERE r.expiresAt < :now")
    int deleteExpired(@Param("now") Instant now);
}
