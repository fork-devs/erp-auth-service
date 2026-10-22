package com.erp.auth.domain.exception;

/**
 * Se lanza cuando una operacion que requiere aislamiento por taller se
 * ejecuta sin contexto de tenant establecido.
 *
 * <p>El aislamiento no se relaxes de forma silenciosa: una operacion sin
 * contexto no se ejecuta sin filtro, se rechaza. Ver
 * docs/doc-estado-implementacion.md, hallazgo P1 6.6.
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
