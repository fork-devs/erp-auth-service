package com.erp.auth.support;

import com.erp.auth.domain.port.UnitOfWork;

import java.util.function.Supplier;

/**
 * Test unit of work implementation executing actions immediately in-line.
 */
public final class DirectUnitOfWork implements UnitOfWork {

    public static final UnitOfWork INSTANCE = new DirectUnitOfWork();

    private DirectUnitOfWork() {
    }

    @Override
    public void runInTransaction(Runnable work) {
        work.run();
    }

    @Override
    public <T> T callInTransaction(Supplier<T> work) {
        return work.get();
    }
}
