package com.erp.auth.support;

import com.erp.auth.domain.model.Role;
import com.erp.auth.domain.model.RoleCode;
import com.erp.auth.domain.port.UserRepositoryPort;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.domain.valueobject.PasswordHash;
import com.erp.auth.domain.valueobject.TenantId;
import com.erp.auth.infrastructure.persistence.rls.TenantContextHolder;
import com.erp.auth.infrastructure.persistence.rls.TenantContextScope;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * El aspecto de Row-Level Security debe ejecutar el SET LOCAL DENTRO de la
 * transaccion. Fuera de ella el SET LOCAL no tiene efecto y la consulta se
 * ejecutaria sin el filtro de aislamiento.
 *
 * <p>El test NO establece el valor de sesion a mano: lo hace el propio
 * aspecto, a partir del contexto de tenant de la aplicacion. Si el orden de
 * los advice no fuera el correcto, la lectura no devolveria la fila.
 *
 * <p>Ver docs/doc-estado-implementacion.md, hallazgo P1 6.6.
 */
class TenantRlsAspectOrderTest extends AbstractPostgresIntegrationTest {

    private static final UUID TENANT_PROPIO = UUID.fromString("44444444-4444-4444-4444-444444444444");
    private static final UUID TENANT_AJENO = UUID.fromString("55555555-5555-5555-5555-555555555555");

    @Autowired
    private UserRepositoryPort userRepositoryPort;

    @Autowired
    private com.erp.auth.domain.port.RoleRepositoryPort roleRepositoryPort;

    @Autowired
    private PlatformTransactionManager transactionManager;

    @AfterEach
    void tearDown() {
        TenantContextHolder.clear();
    }

    @Test
    void elAspectoEstableceElContextoDentroDeLaTransaccion() throws Exception {
        Role asesor = roleRepositoryPort.findByCode(RoleCode.ASESOR)
                .orElseThrow(() -> new AssertionError("El rol ASESOR deberia estar sembrado"));

        UUID userId = UUID.randomUUID();
        crearUsuario(asesor.getId(), userId, TENANT_PROPIO, "orden@driveos.pe");

        // El contexto de la APLICACION es lo unico que se establece: el valor de
        // sesion lo pone el aspecto, y solo puede ponerlo dentro de la
        // transaccion.
        Optional<?> encontrado = conTenant(TENANT_PROPIO,
                () -> userRepositoryPort.findByIdAndTenantId(userId, new TenantId(TENANT_PROPIO)));

        assertTrue(encontrado.isPresent(),
                "El usuario debe verse: el aspecto tiene que haber establecido el contexto dentro de la transaccion");
    }

    @Test
    void conElTenantAjenoLaFilaNoSeVe() throws Exception {
        Role asesor = roleRepositoryPort.findByCode(RoleCode.ASESOR)
                .orElseThrow(() -> new AssertionError("El rol ASESOR deberia estar sembrado"));

        UUID userId = UUID.randomUUID();
        crearUsuario(asesor.getId(), userId, TENANT_PROPIO, "ajeno@driveos.pe");

        Optional<?> encontrado = conTenant(TENANT_AJENO,
                () -> userRepositoryPort.findByIdAndTenantId(userId, new TenantId(TENANT_AJENO)));

        assertTrue(encontrado.isEmpty(),
                "Con el contexto de otro taller la fila no debe verse");
    }

    private void crearUsuario(UUID roleId, UUID userId, UUID tenantId, String email) throws Exception {
        try (var connection = EmbeddedPostgresSupport.openOwnerConnection();
             var statement = connection.createStatement()) {
            statement.execute("INSERT INTO users (id, tenant_id, email, password_hash, created_at) VALUES ('"
                    + userId + "', '" + tenantId + "', '" + email + "', 'hash', now())");
            statement.execute("INSERT INTO user_roles (user_id, role_id, tenant_id) VALUES ('"
                    + userId + "', '" + roleId + "', '" + tenantId + "')");
        }
    }

    private <T> T conTenant(UUID tenantId, java.util.function.Supplier<T> operacion) {
        try (TenantContextScope scope = TenantContextScope.forTenant(tenantId)) {
            TransactionTemplate template = new TransactionTemplate(transactionManager);
            return template.execute(status -> operacion.get());
        }
    }
}
