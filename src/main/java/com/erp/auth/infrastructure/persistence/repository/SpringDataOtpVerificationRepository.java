package com.erp.auth.infrastructure.persistence.repository;

import com.erp.auth.infrastructure.persistence.entity.OtpVerificationJpaEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface SpringDataOtpVerificationRepository extends JpaRepository<OtpVerificationJpaEntity, UUID> {

    @Query("SELECT o FROM OtpVerificationJpaEntity o WHERE o.email = :email ORDER BY o.createdAt DESC LIMIT 1")
    Optional<OtpVerificationJpaEntity> findLatestByEmail(@Param("email") String email);

    @Modifying
    @Query("UPDATE OtpVerificationJpaEntity o SET o.attempts = o.attempts + 1 WHERE o.id = :id")
    void incrementAttempts(@Param("id") UUID id);

    @Modifying
    @Query("UPDATE OtpVerificationJpaEntity o SET o.verified = true WHERE o.email = :email AND o.verified = false")
    void invalidateAllPendingByEmail(@Param("email") String email);
}
