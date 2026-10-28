package com.erp.auth.infrastructure.persistence.rls;

import java.util.UUID;

/**
 * Thread-local holder for the active request's tenant context.
 *
 * <p>Set exclusively from verified tokens or initial authentication flows, and cleared
 * upon request completion.
 *
 * <p>Fails closed with no bypass mechanism: the former {@code app.bypass_rls} session variable
 * has been removed. See docs/doc-estado-implementacion.md, finding P1 6.6.
 */
public final class TenantContextHolder {

    private static final ThreadLocal<UUID> CURRENT_TENANT = new ThreadLocal<>();

    private TenantContextHolder() {}

    public static void setTenantId(UUID tenantId) {
        CURRENT_TENANT.set(tenantId);
    }

    public static UUID getTenantId() {
        return CURRENT_TENANT.get();
    }

    public static void clear() {
        CURRENT_TENANT.remove();
    }
}
