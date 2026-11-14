package com.erp.auth.infrastructure.persistence;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.annotation.Pointcut;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * Automated AOP Aspect for persistence write methods.
 *
 * Enforces two critical transactional requirements before any mutation method executes:
 * 1. An active transaction MUST exist (no standalone commits in persistence layer).
 * 2. The active transaction MUST NOT be read-only (prevents silent write drop/failure).
 *
 * This completely eliminates reliance on manual calls to TransactionGuard and prevents bypasses.
 */
@Aspect
@Component
@Order(10)
public class PersistenceTransactionGuardAspect {

    @Pointcut("execution(* com.erp.auth.infrastructure.persistence.adapter..save*(..))"
            + " || execution(* com.erp.auth.infrastructure.persistence.adapter..delete*(..))"
            + " || execution(* com.erp.auth.infrastructure.persistence.adapter..revoke*(..))"
            + " || execution(* com.erp.auth.infrastructure.persistence.adapter..invalidate*(..))"
            + " || execution(* com.erp.auth.infrastructure.persistence.adapter..store*(..))"
            + " || execution(* com.erp.auth.infrastructure.persistence.adapter..consume*(..))"
            + " || execution(* com.erp.auth.infrastructure.persistence.adapter..increment*(..))"
            + " || execution(* com.erp.auth.infrastructure.persistence.adapter..record*(..))")
    public void persistenceMutationMethods() {
    }

    @Before("persistenceMutationMethods()")
    public void requireActiveReadWriteTransaction(JoinPoint joinPoint) {
        String methodName = joinPoint.getSignature().getName();
        if (!TransactionSynchronizationManager.isActualTransactionActive()) {
            throw new MissingTransactionBoundaryException(methodName);
        }
        if (TransactionSynchronizationManager.isCurrentTransactionReadOnly()) {
            throw new IllegalStateException("Operation " + methodName + " is a write mutation and cannot run inside a read-only transaction");
        }
    }
}
