package com.erp.auth.infrastructure.persistence.adapter;

import com.erp.auth.domain.valueobject.TenantId;
import com.erp.auth.domain.valueobject.UserId;
import com.erp.auth.infrastructure.persistence.TransactionGuard;
import com.erp.auth.infrastructure.persistence.repository.SpringDataRefreshTokenRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.UUID;

import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("Infrastructure - RefreshTokenPersistenceAdapter Multi-Tenant Test")
class RefreshTokenPersistenceAdapterTest {

    @Mock
    private SpringDataRefreshTokenRepository springDataRefreshTokenRepository;

    @Mock
    private TransactionGuard transactionGuard;

    private RefreshTokenPersistenceAdapter adapter;

    @BeforeEach
    void setUp() {
        adapter = new RefreshTokenPersistenceAdapter(springDataRefreshTokenRepository, transactionGuard);
    }

    @Test
    @DisplayName("revokeAllByUserId with UserId and TenantId must pass both to SpringData query and guard transaction")
    void shouldRevokeAllByUserIdAndTenantId() {
        UserId userId = UserId.generate();
        TenantId tenantId = TenantId.generate();

        adapter.revokeAllByUserId(userId, tenantId);

        verify(transactionGuard).requireActiveTransaction("revokeAllByUserId");
        verify(springDataRefreshTokenRepository).revokeAllByUserIdAndTenantId(userId.getValue(), tenantId.getValue());
        verifyNoMoreInteractions(springDataRefreshTokenRepository);
    }
}
