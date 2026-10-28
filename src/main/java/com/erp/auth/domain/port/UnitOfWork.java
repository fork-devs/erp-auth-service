package com.erp.auth.domain.port;

import java.util.function.Supplier;

/**
 * Transaction boundary for domain and application operations.
 *
 * <p>A domain-level abstraction without framework dependencies, enabling the
 * application layer to enforce atomic operations spanning multiple repository
 * writes regardless of the underlying transactional mechanism.
 *
 * <p>Without an explicit unit of work, each repository call commits independently:
 * sequential writes become separate transactions, breaking atomicity guarantees.
 * Refresh token rotation is a primary example: if revoking the old token succeeds
 * but issuing the new token fails, the session is stranded without any valid token.
 */
public interface UnitOfWork {

    void runInTransaction(Runnable work);

    <T> T callInTransaction(Supplier<T> work);
}
