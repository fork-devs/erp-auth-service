package com.erp.auth.infrastructure.persistence.rls;

import java.util.UUID;

/**
 * Establece el contexto de tenant durante el ambito de una operacion y lo
 * restaura al terminar.
 *
 * <p>Se usa en los flujos de ARRANQUE (inicio de sesion, renovacion de token y
 * restablecimiento de contraseña), donde todavia no existe un token de acceso
 * verificado del que deducir el tenant.
 *
 * <p>En esos flujos el tenant lo declara el cliente y funciona como FILTRO,
 * nunca como autoridad: la politica de Row-Level Security exige que la fila
 * buscada pertenezca a ese tenant, de modo que declararlo no puede ampliar el
 * acceso, solo acotarlo. En cuanto la fila se ha localisation, el tenant
 * autoritativo es el de la propia fila.
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
