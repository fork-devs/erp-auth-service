package com.erp.auth.infrastructure.persistence.repository;

import com.erp.auth.infrastructure.persistence.entity.UserJpaEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface SpringDataUserRepository extends JpaRepository<UserJpaEntity, UUID> {

    Optional<UserJpaEntity> findByEmailAndTenantId(String email, UUID tenantId);

    Optional<UserJpaEntity> findByIdAndTenantId(UUID id, UUID tenantId);

    boolean existsByEmailAndTenantId(String email, UUID tenantId);

    List<UserJpaEntity> findAllByTenantId(UUID tenantId);
}
