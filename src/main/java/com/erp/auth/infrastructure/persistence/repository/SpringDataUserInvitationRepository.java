package com.erp.auth.infrastructure.persistence.repository;

import com.erp.auth.infrastructure.persistence.entity.UserInvitationJpaEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface SpringDataUserInvitationRepository extends JpaRepository<UserInvitationJpaEntity, UUID> {

    Optional<UserInvitationJpaEntity> findByTokenHash(String tokenHash);

    Optional<UserInvitationJpaEntity> findFirstByEmailAndTenantIdOrderByCreatedAtDesc(String email, UUID tenantId);

    @Modifying
    @Query("UPDATE UserInvitationJpaEntity u SET u.expiresAt = :now WHERE u.email = :email AND u.tenantId = :tenantId AND u.acceptedAt IS NULL")
    void invalidateAllByEmailAndTenantId(@Param("email") String email, @Param("tenantId") UUID tenantId, @Param("now") Instant now);
}
