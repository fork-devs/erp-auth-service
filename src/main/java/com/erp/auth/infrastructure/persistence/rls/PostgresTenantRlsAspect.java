package com.erp.auth.infrastructure.persistence.rls;

import jakarta.persistence.EntityManager;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Aspect
@Component
public class PostgresTenantRlsAspect {

    private final EntityManager entityManager;

    public PostgresTenantRlsAspect(EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    @Before("execution(* com.erp.auth.infrastructure.persistence.adapter..*(..))")
    public void setPostgresTenantContext() {
        if (TenantContextHolder.isBypassRls()) {
            try {
                entityManager.createNativeQuery("SET LOCAL app.bypass_rls = 'on'").executeUpdate();
            } catch (Exception ignored) {
                // Si la sesión no está en una transacción activa, se ignora de forma segura
            }
            return;
        }

        UUID tenantId = TenantContextHolder.getTenantId();
        if (tenantId != null) {
            try {
                entityManager.createNativeQuery("SET LOCAL app.tenant_id = '" + tenantId + "'").executeUpdate();
            } catch (Exception ignored) {
                // Silencioso si no hay transacción activa
            }
        }
    }
}
