package com.erp.auth.infrastructure.persistence;

import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * Guard component verifying that an active, read-write transaction boundary exists.
 *
 * <p>Persistence adapters join transactions opened by the application layer.
 * This guard ensures that calling an adapter without an active transaction or within
 * a read-only transaction fails explicitly rather than silently committing writes or violating boundaries.
 */
@Component
public class TransactionGuard {

    public void requireActiveTransaction(String operacion) {
        if (!TransactionSynchronizationManager.isActualTransactionActive()) {
            throw new MissingTransactionBoundaryException(operacion);
        }
        if (TransactionSynchronizationManager.isCurrentTransactionReadOnly()) {
            throw new IllegalStateException("Operation " + operacion + " is a write mutation and cannot run inside a read-only transaction");
        }
    }
}
