package com.erp.auth.infrastructure.persistence.adapter;

import com.erp.auth.domain.valueobject.TenantId;
import com.erp.auth.domain.valueobject.UserId;
import com.erp.auth.infrastructure.persistence.TransactionGuard;
import com.erp.auth.infrastructure.persistence.repository.SpringDataPasswordResetTokenRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("Infrastructure - PasswordResetTokenPersistenceAdapter Multi-Tenant Test")
class PasswordResetTokenPersistenceAdapterTest {

    @Mock
    private SpringDataPasswordResetTokenRepository repository;

    @Mock
    private TransactionGuard transactionGuard;

    private PasswordResetTokenPersistenceAdapter adapter;

    @BeforeEach
    void setUp() {
        adapter = new PasswordResetTokenPersistenceAdapter(repository, transactionGuard);
    }

    @Test
    @DisplayName("invalidateAllByUserId with UserId and TenantId must pass both to SpringData query and guard transaction")
    void shouldInvalidateAllByUserIdAndTenantId() {
        UserId userId = UserId.generate();
        TenantId tenantId = TenantId.generate();

        adapter.invalidateAllByUserId(userId, tenantId);

        verify(transactionGuard).requireActiveTransaction("invalidateAllByUserId");
        verify(repository).invalidateAllByUserIdAndTenantId(eq(userId.value()), eq(tenantId.value()), any(Instant.class));
        verifyNoMoreInteractions(repository);
    }
}
