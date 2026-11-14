package com.erp.auth.infrastructure.persistence.rls;

import java.util.UUID;

/**
 * Thread-local holder for the active request's tenant context.
 *
 * Uses InheritableThreadLocal to ensure seamless propagation across child threads,
 * async tasks (@Async), and virtual threads.
 */
public final class TenantContextHolder {

    private static final ThreadLocal<UUID> CURRENT_TENANT = new InheritableThreadLocal<>();

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
