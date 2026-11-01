package com.erp.auth.infrastructure.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.transaction.annotation.EnableTransactionManagement;

/**
 * Configuration of transactional boundaries and aspect precedence.
 *
 * <p>Advice ordering is critical: Spring's transaction interceptor and the tenant RLS aspect
 * compete for precedence. Without explicit ordering, the order is non-deterministic and
 * {@code SET LOCAL} could execute OUTSIDE the transaction where it has no effect, causing queries
 * to execute without tenant isolation filters.
 *
 * <p>With the transaction interceptor configured at order 0 and the RLS aspect at order 1,
 * the aspect executes INSIDE the transaction boundary where {@code SET LOCAL} takes effect.
 *
 * <p>See docs/doc-estado-implementacion.md, finding P1 6.6.
 */
@Configuration
@EnableTransactionManagement(order = 0)
public class PersistenceConfig {

    /**
     * Order of the Row-Level Security aspect. In Spring, lower order values indicate
     * higher precedence (outer advice). The RLS aspect must be INNER to the transaction
     * interceptor (order > 0).
     */
    public static final int TENANT_RLS_ASPECT_ORDER = 1;
}
