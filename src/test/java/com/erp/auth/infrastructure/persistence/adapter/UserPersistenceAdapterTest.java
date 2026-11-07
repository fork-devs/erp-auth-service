package com.erp.auth.infrastructure.persistence.adapter;

import com.erp.auth.domain.valueobject.TenantId;
import com.erp.auth.domain.valueobject.UserId;
import com.erp.auth.infrastructure.persistence.TransactionGuard;
import com.erp.auth.infrastructure.persistence.repository.SpringDataRoleRepository;
import com.erp.auth.infrastructure.persistence.repository.SpringDataUserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.UUID;

import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("Infrastructure - UserPersistenceAdapter Multi-Tenant Test")
class UserPersistenceAdapterTest {

    @Mock
    private SpringDataUserRepository springDataUserRepository;

    @Mock
    private SpringDataRoleRepository springDataRoleRepository;

    @Mock
    private TransactionGuard transactionGuard;

    private UserPersistenceAdapter adapter;

    @BeforeEach
    void setUp() {
        adapter = new UserPersistenceAdapter(springDataUserRepository, springDataRoleRepository, transactionGuard);
    }

    @Test
    @DisplayName("deleteById with UserId and TenantId must pass both to SpringData query and guard transaction")
    void shouldDeleteByIdAndTenantId() {
        UserId userId = UserId.generate();
        TenantId tenantId = TenantId.generate();

        adapter.deleteById(userId, tenantId);

        verify(transactionGuard).requireActiveTransaction("deleteUser");
        verify(springDataUserRepository).deleteByIdAndTenantId(userId.getValue(), tenantId.getValue());
        verifyNoMoreInteractions(springDataUserRepository);
    }
}
