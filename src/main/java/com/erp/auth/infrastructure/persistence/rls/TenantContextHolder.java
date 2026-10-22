package com.erp.auth.infrastructure.persistence.rls;

import java.util.UUID;

/**
 * Contexto de tenant de la peticion en curso.
 *
 * <p>Solo se establece desde un token verificado o desde el tenant de
 * arranque de los flujos de autenticacion, y se limpia al terminar la
 * peticion.
 *
 * <p>No existe ningun mecanismo para eludir el aislamiento: el hueco
 * {@code app.bypass_rls} que permitia desactivar la politica de
 * Row-Level Security con una session variable se ha eliminado, porque era
 * una instruccion SQL susceptible de activar y de desactivar el aislamiento
 * por completo. Ver docs/doc-estado-implementacion.md, hallazgo P1 6.6.
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
