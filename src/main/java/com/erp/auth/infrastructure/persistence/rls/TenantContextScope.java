package com.erp.auth.infrastructure.persistence.rls;

import java.util.UUID;

/**
 * Scopes tenant context for the duration of a block and restores previous context upon close.
 *
 * <p>Used during bootstrap flows (login, token refresh, password reset) where a verified
 * access token is not yet present to provide the tenant context.
 *
 * <p>In these flows, the client-provided tenant acts strictly as a filter rather than an authority:
 * Row-Level Security requires rows to match this tenant, narrowing access rather than broadening it.
 */
public final class TenantContextScope implements AutoCloseable {

    private final UUID previousTenantId;
    private boolean closed;

    private TenantContextScope(UUID previousTenantId) {
        this.previousTenantId = previousTenantId;
    }

    public static TenantContextScope forTenant(UUID tenantId) {
        UUID previous = TenantContextHolder.getTenantId();
        TenantContextHolder.setTenantId(tenantId);
        return new TenantContextScope(previous);
    }

    @Override
    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        if (previousTenantId == null) {
            TenantContextHolder.clear();
        } else {
            TenantContextHolder.setTenantId(previousTenantId);
        }
    }
}
