package com.erp.auth.infrastructure.persistence;

import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * Guard component verifying that an active transaction boundary exists.
 *
 * <p>Persistence adapters join transactions opened by the application layer.
 * This guard ensures that calling an adapter without an active transaction fails
 * explicitly rather than silently auto-committing writes in isolation.
 */
@Component
public class TransactionGuard {

    public void requireActiveTransaction(String operacion) {
        if (!TransactionSynchronizationManager.isActualTransactionActive()) {
            throw new MissingTransactionBoundaryException(operacion);
        }
    }
}
