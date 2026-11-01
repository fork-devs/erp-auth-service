package com.erp.auth.infrastructure.persistence.rls;

import com.erp.auth.domain.exception.TenantContextMissingException;
import com.erp.auth.infrastructure.config.PersistenceConfig;
import jakarta.persistence.EntityManager;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.core.annotation.Order;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.util.UUID;

/**
 * Sets the tenant context on the PostgreSQL database session so Row-Level Security (RLS)
 * policies can enforce tenant row filtering.
 *
 * <p>Isolation fails closed: without an active transaction, {@code SET LOCAL} would have
 * no effect and queries would execute unfiltered. Therefore operations are rejected
 * rather than executed without isolation. See docs/doc-estado-implementacion.md, finding P1 6.6.
 */
@Aspect
@Component
@Order(PersistenceConfig.TENANT_RLS_ASPECT_ORDER)
public class PostgresTenantRlsAspect {

    private final EntityManager entityManager;

    @Autowired
    public PostgresTenantRlsAspect(EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    /**
     * Ensures all persistence operations run within an active transaction.
     * Outside a transaction, tenant context cannot be bound via {@code SET LOCAL}.
     */
    @Before("execution(* com.erp.auth.infrastructure.persistence.adapter..*(..))")
    public void requireActiveTransaction() {
        if (!TransactionSynchronizationManager.isActualTransactionActive()) {
            throw new TenantContextMissingException(
                    "La operacion de persistencia debe ejecutarse dentro de una transaccion: "
                    + "fuera de ella no puede garantizarse el aislamiento por taller.");
        }
    }

    /**
     * Enforces tenant context for tenant-owned tables. Global catalog tables (such as
     * {@code roles}) are exempt as they are shared across all tenants.
     *
     * <p>The UUID value is interpolated into the statement because PostgreSQL {@code SET LOCAL}
     * does not support parameterized queries; the pre-validated UUID prevents SQL injection.
     */
    @Before("execution(* com.erp.auth.infrastructure.persistence.adapter.UserPersistenceAdapter.*(..))"
            + " || execution(* com.erp.auth.infrastructure.persistence.adapter.RefreshTokenPersistenceAdapter.*(..))"
            + " || execution(* com.erp.auth.infrastructure.persistence.adapter.PasswordResetTokenPersistenceAdapter.*(..))"
            + " || execution(* com.erp.auth.infrastructure.persistence.adapter.SecondFactorPersistenceAdapter.*(..))")
    public void applyTenantContext() {
        UUID tenantId = TenantContextHolder.getTenantId();
        if (tenantId == null) {
            throw new TenantContextMissingException(
                    "La operacion requiere un contexto de taller establecido y no lo tiene.");
        }
        entityManager.createNativeQuery("SET LOCAL app.tenant_id = '" + tenantId + "'").executeUpdate();
    }
}
