package com.erp.auth.infrastructure.persistence;

import com.erp.auth.infrastructure.persistence.rls.TenantContextHolder;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.Signature;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("Infrastructure - PersistenceTransactionGuardAspect Test")
class PersistenceTransactionGuardAspectTest {

    private PersistenceTransactionGuardAspect aspect;

    @Mock
    private JoinPoint joinPoint;

    @Mock
    private Signature signature;

    @BeforeEach
    void setUp() {
        aspect = new PersistenceTransactionGuardAspect();
        org.mockito.Mockito.lenient().when(joinPoint.getSignature()).thenReturn(signature);
        org.mockito.Mockito.lenient().when(signature.getName()).thenReturn("saveUser");
    }

    @AfterEach
    void tearDown() {
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.clearSynchronization();
        }
        TransactionSynchronizationManager.setActualTransactionActive(false);
        TransactionSynchronizationManager.setCurrentTransactionReadOnly(false);
        TenantContextHolder.clear();
    }

    @Test
    @DisplayName("Should throw MissingTransactionBoundaryException when no transaction is active")
    void shouldThrowWhenNoTransactionActive() {
        TransactionSynchronizationManager.setActualTransactionActive(false);

        assertThatThrownBy(() -> aspect.requireActiveReadWriteTransaction(joinPoint))
                .isInstanceOf(MissingTransactionBoundaryException.class)
                .hasMessageContaining("saveUser");
    }

    @Test
    @DisplayName("Should throw IllegalStateException when transaction is active but read-only")
    void shouldThrowWhenTransactionIsReadOnly() {
        TransactionSynchronizationManager.setActualTransactionActive(true);
        TransactionSynchronizationManager.setCurrentTransactionReadOnly(true);

        assertThatThrownBy(() -> aspect.requireActiveReadWriteTransaction(joinPoint))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("cannot run inside a read-only transaction");
    }

    @Test
    @DisplayName("Should succeed when transaction is active and read-write")
    void shouldSucceedWhenTransactionIsActiveAndReadWrite() {
        TransactionSynchronizationManager.setActualTransactionActive(true);
        TransactionSynchronizationManager.setCurrentTransactionReadOnly(false);

        aspect.requireActiveReadWriteTransaction(joinPoint);
    }

    @Test
    @DisplayName("Should propagate TenantContext across child threads via InheritableThreadLocal")
    void shouldPropagateTenantContextAcrossThreads() throws Exception {
        UUID tenantId = UUID.randomUUID();
        TenantContextHolder.setTenantId(tenantId);

        java.util.concurrent.atomic.AtomicReference<UUID> childThreadTenantId = new java.util.concurrent.atomic.AtomicReference<>();
        Thread child = new Thread(() -> childThreadTenantId.set(TenantContextHolder.getTenantId()));
        child.start();
        child.join();

        assertThat(childThreadTenantId.get()).isEqualTo(tenantId);
    }
}
