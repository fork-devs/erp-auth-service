package com.erp.auth.infrastructure.config;

import com.erp.auth.domain.port.UnitOfWork;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.function.Supplier;

/**
 * Implementation of the domain unit of work boundary backed by {@link TransactionTemplate}.
 *
 * <p>Employs default propagation: if a transaction is already active, the operation joins it
 * rather than starting a new one, enabling nested demarcations without independent commits.
 */
@Component
public class UnitOfWorkAdapter implements UnitOfWork {

    private final TransactionTemplate transactionTemplate;

    public UnitOfWorkAdapter(PlatformTransactionManager transactionManager) {
        this.transactionTemplate = new TransactionTemplate(transactionManager);
    }

    @Override
    public void runInTransaction(Runnable work) {
        transactionTemplate.executeWithoutResult(status -> work.run());
    }

    @Override
    public <T> T callInTransaction(Supplier<T> work) {
        return transactionTemplate.execute(status -> work.get());
    }
}
