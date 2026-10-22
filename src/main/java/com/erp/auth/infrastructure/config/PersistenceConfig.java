package com.erp.auth.infrastructure.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.transaction.annotation.EnableTransactionManagement;

/**
 * Configuracion de la demarcacion transaccional.
 *
 * <p>El orden de los advice importa: el interceptor transaccional de Spring y
 * el aspecto que establece el contexto de tenant compiten por el mismo
 * orden. Sin fijarlo, el orden es indeterminado y el {@code SET LOCAL} puede
 * ejecutarse FUERA de la transaccion, donde no tiene efecto: la consulta
 * se ejecutaria sin el filtro de aislamiento.
 *
 * <p>Con el interceptor transaccional en el orden 0 y el aspecto en el
 * orden 1, el aspecto queda DENTRO de la transaccion, que es donde el
 * {@code SET LOCAL} es aplicable.
 *
 * <p>Ver docs/doc-estado-implementacion.md, hallazgo P1 6.6.
 */
@Configuration
@EnableTransactionManagement(order = 0)
public class PersistenceConfig {

    /**
     * Orden del aspecto de Row-Level Security. En Spring, un valor de orden
     * MENOR significa mayor precedencia y, por tanto, un advice EXTERIOR. El
     * aspecto debe ser INTERIOR al interceptor transaccional, de modo que su
     * orden sea mayor que el de este ultimo.
     */
    public static final int TENANT_RLS_ASPECT_ORDER = 1;
}
