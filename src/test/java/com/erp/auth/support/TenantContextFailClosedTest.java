package com.erp.auth.support;

import com.erp.auth.domain.exception.TenantContextMissingException;
import com.erp.auth.infrastructure.persistence.rls.PostgresTenantRlsAspect;
import com.erp.auth.infrastructure.persistence.rls.TenantContextHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tenant isolation fails closed: any persistence operation executing outside
 * an active transaction cannot set the session tenant context, which would cause
 * Row-Level Security policies to execute unfiltered. In this scenario, the operation
 * is rejected immediately.
 */
class TenantContextFailClosedTest extends AbstractPostgresIntegrationTest {

    @Autowired
    private PlatformTransactionManager transactionManager;

    @Autowired
    private PostgresTenantRlsAspect aspect;

    @AfterEach
    void tearDown() {
        TenantContextHolder.clear();
    }

    @Test
    void fueraDeTransaccionLaOperacionSeRechaza() {
        TenantContextMissingException ex = assertThrows(TenantContextMissingException.class,
                () -> aspect.requireActiveTransaction(),
                "Sin transaccion activa la operacion debe rechazarse");
        assertTrue(ex.getMessage().contains("transaccion"),
                "El mensaje debe explicar que falta la transaccion");
    }

    @Test
    void dentroDeTransaccionLaOperacionContinua() {
        TransactionTemplate template = new TransactionTemplate(transactionManager);
        assertDoesNotThrow(() -> template.execute(status -> {
            aspect.requireActiveTransaction();
            return null;
        }));
    }

    @Test
    void sinContextoDeTenantLaOperacionSeRechaza() {
        TenantContextHolder.clear();
        TransactionTemplate template = new TransactionTemplate(transactionManager);
        assertThrows(TenantContextMissingException.class, () -> template.execute(status -> {
            aspect.requireActiveTransaction();
            aspect.applyTenantContext();
            return null;
        }), "Sin contexto de tenant la operacion debe rechazarse");
    }
}
