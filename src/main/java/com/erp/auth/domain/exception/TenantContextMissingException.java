package com.erp.auth.domain.exception;

/**
 * Thrown when an operation that requires workshop tenant isolation is executed
 * without an established tenant context.
 *
 * <p>Isolation does not fail open: an operation without context is rejected rather
 * than executed without tenant filters. See docs/doc-estado-implementacion.md, finding P1 6.6.
 */
public class TenantContextMissingException extends DomainException {

    public TenantContextMissingException() {
        super("AUTH_TENANT_CONTEXT_MISSING",
                "La operacion requiere un contexto de taller establecido y no lo tiene.");
    }

    public TenantContextMissingException(String message) {
        super("AUTH_TENANT_CONTEXT_MISSING", message);
    }
}
