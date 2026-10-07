package com.erp.auth.infrastructure.persistence.rls;

import java.util.UUID;

public final class TenantContextHolder {

    private static final ThreadLocal<UUID> CURRENT_TENANT = new ThreadLocal<>();
    private static final ThreadLocal<Boolean> BYPASS_RLS = ThreadLocal.withInitial(() -> false);

    private TenantContextHolder() {}

    public static void setTenantId(UUID tenantId) {
        CURRENT_TENANT.set(tenantId);
    }

    public static UUID getTenantId() {
        return CURRENT_TENANT.get();
    }

    public static void setBypassRls(boolean bypass) {
        BYPASS_RLS.set(bypass);
    }

    public static boolean isBypassRls() {
        return Boolean.TRUE.equals(BYPASS_RLS.get());
    }

    public static void clear() {
        CURRENT_TENANT.remove();
        BYPASS_RLS.remove();
    }
}
