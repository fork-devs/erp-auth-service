package com.erp.auth.infrastructure.persistence.adapter;

import com.erp.auth.domain.valueobject.TenantId;
import com.erp.auth.domain.valueobject.UserId;
import com.erp.auth.infrastructure.persistence.TransactionGuard;
import com.erp.auth.infrastructure.persistence.entity.RevokedTokenJpaEntity;
import com.erp.auth.infrastructure.persistence.repository.SpringDataRevokedTokenRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("Infrastructure - RevokedTokenPersistenceAdapter High-Speed TTL Test")
class RevokedTokenPersistenceAdapterTest {

    @Mock
    private SpringDataRevokedTokenRepository repository;

    @Mock
    private TransactionGuard transactionGuard;

    private RevokedTokenPersistenceAdapter adapter;

    @BeforeEach
    void setUp() {
        adapter = new RevokedTokenPersistenceAdapter(repository, transactionGuard);
    }

    @Test
    @DisplayName("Should store token with fast TTL and verify isRevoked without database query on warm cache")
    void shouldStoreTokenAndVerifyFastTtl() {
        UUID tokenId = UUID.randomUUID();
        UserId userId = UserId.generate();
        TenantId tenantId = TenantId.generate();
        Instant futureExpires = Instant.now().plusSeconds(600);

        when(repository.existsById(tokenId)).thenReturn(false);

        adapter.revoke(tokenId, userId, tenantId, futureExpires);

        verify(transactionGuard).requireActiveTransaction("revokeToken");
        verify(repository).save(any(RevokedTokenJpaEntity.class));

        // Subsequent check should be served from fast in-memory TTL store without calling DB existsById again
        clearInvocations(repository);
        boolean isRevoked = adapter.isRevoked(tokenId);

        assertThat(isRevoked).isTrue();
        verify(repository, never()).existsById(any());
    }

    @Test
    @DisplayName("Should be strictly idempotent when revoking same token twice")
    void shouldBeStrictlyIdempotent() {
        UUID tokenId = UUID.randomUUID();
        UserId userId = UserId.generate();
        TenantId tenantId = TenantId.generate();
        Instant futureExpires = Instant.now().plusSeconds(600);

        when(repository.existsById(tokenId)).thenReturn(true);

        adapter.revoke(tokenId, userId, tenantId, futureExpires);

        // Does not re-save
        verify(repository, never()).save(any());
    }

    @Test
    @DisplayName("Should throw UnsupportedOperationException on legacy revocation without TenantId")
    void shouldRejectLegacyRevocationWithoutTenantId() {
        UUID tokenId = UUID.randomUUID();
        UUID userId = UUID.randomUUID();

        assertThatThrownBy(() -> adapter.revoke(tokenId, userId, Instant.now()))
                .isInstanceOf(UnsupportedOperationException.class)
                .hasMessageContaining("Multi-tenant safety");
    }
}
