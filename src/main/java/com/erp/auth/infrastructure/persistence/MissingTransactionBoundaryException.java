package com.erp.auth.infrastructure.persistence;

/**
 * Infrastructure exception thrown when a persistence operation is invoked
 * outside an active transaction boundary.
 *
 * <p>Persistence adapters join the transaction demarcated by the application layer
 * rather than opening their own. If invoked without one, sequential writes would commit
 * independently and break atomicity guarantees.
 *
 * <p>See docs/doc-estado-implementacion.md, findings P0 5.3 and P0 5.8.
 */
public class MissingTransactionBoundaryException extends RuntimeException {

    public MissingTransactionBoundaryException(String operacion) {
        super("La operacion de persistencia '" + operacion
                + "' requiere un limite transaccional abierto por la capa de aplicacion. "
                + "Los adaptadores se unen a la transaccion en curso; no abren una propia.");
    }
}
