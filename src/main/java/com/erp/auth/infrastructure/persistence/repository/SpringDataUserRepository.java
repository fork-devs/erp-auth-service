package com.erp.auth.infrastructure.persistence.repository;

import com.erp.auth.infrastructure.persistence.entity.UserJpaEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.time.Instant;
import java.util.UUID;

@Repository
public interface SpringDataUserRepository extends JpaRepository<UserJpaEntity, UUID> {

    Optional<UserJpaEntity> findByEmailAndTenantId(String email, UUID tenantId);

    Optional<UserJpaEntity> findByIdAndTenantId(UUID id, UUID tenantId);

    boolean existsByEmailAndTenantId(String email, UUID tenantId);

    /**
     * Second-factor authentication state projection for a user.
     *
     * <p>Retrieved as a PROJECTION rather than the full entity to avoid attaching
     * the entity to the Hibernate persistence context, preventing detached-entity
     * conflict during subsequent updates.
     */
    @Query("SELECT u.mfaSecretCiphertext AS mfaSecretCiphertext, "
            + "u.mfaLastCodeCounter AS mfaLastCodeCounter, u.version AS version "
            + "FROM UserJpaEntity u WHERE u.id = :id")
    java.util.Optional<UserState> findUserState(@Param("id") UUID id);

    /**
     * User state projection holding infrastructure-specific row attributes absent
     * from the domain model: encrypted 2FA secret, last accepted code counter, and
     * optimistic concurrency version.
     */
    interface UserState {
        String getMfaSecretCiphertext();

        Long getMfaLastCodeCounter();

        Long getVersion();
    }

    /**
     * Atomically increments the failed login attempt counter directly in the database.
     *
     * <p>The increment is executed as an atomic SQL statement: concurrent failed attempts
     * cannot overwrite each other, preventing lost updates.
     *
     * <p>The lockout condition is evaluated in the same atomic statement: when the
     * counter reaches {@code maxAttempts}, the account is locked until {@code lockedUntil}.
     */
    @Modifying
    @Query("UPDATE UserJpaEntity u SET u.failedAttempts = u.failedAttempts + 1, "
            + "u.lockedUntil = CASE WHEN u.failedAttempts + 1 >= :maxAttempts THEN :lockedUntil ELSE u.lockedUntil END "
            + "WHERE u.id = :id")
    int incrementFailedAttempts(@Param("id") UUID id,
                                @Param("maxAttempts") int maxAttempts,
                                @Param("lockedUntil") Instant lockedUntil);

    List<UserJpaEntity> findAllByTenantId(UUID tenantId);
}
