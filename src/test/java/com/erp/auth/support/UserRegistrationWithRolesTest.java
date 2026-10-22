package com.erp.auth.support;

import com.erp.auth.domain.model.Role;
import com.erp.auth.domain.model.RoleCode;
import com.erp.auth.domain.model.User;
import com.erp.auth.domain.port.UserRepositoryPort;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.domain.valueobject.PasswordHash;
import com.erp.auth.domain.valueobject.TenantId;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifica que el alta de un usuario con roles persiste contra PostgreSQL real.
 *
 * <p>Con el mapeo anterior, la tabla user_roles se escribia mediante un
 * {@code @JoinTable} de dos columnas, de modo que la columna tenant_id
 * quedaba sin valor y el INSERT violaba su restriccion NOT NULL. El defecto
 * quedaba oculto porque los tests usaban H2 con el esquema derivado de las
 * entidades, donde esa columna no existia.
 *
 * <p>Las escrituras se ejecutan con el contexto de tenant establecido, que es
 * lo que hace el aspecto de Row-Level Security en produccion. Sin ese
 * contexto, la politica de aislamiento rechaza la escritura: el aislamiento
 * es fail-closed tambien en la escritura.
 */
class UserRegistrationWithRolesTest extends AbstractPostgresIntegrationTest {

    private static final UUID TENANT_ID = UUID.fromString("33333333-3333-3333-3333-333333333333");

    @Autowired
    private UserRepositoryPort userRepositoryPort;

    @Autowired
    private com.erp.auth.domain.port.RoleRepositoryPort roleRepositoryPort;

    @Autowired
    private PlatformTransactionManager transactionManager;

    @Autowired
    private org.springframework.jdbc.core.JdbcTemplate jdbcTemplate;

    @Test
    void laFilaDeLaTablaIntermediaContieneElTallerCorrecto() throws Exception {
        Role asesor = roleRepositoryPort.findByCode(RoleCode.ASESOR)
                .orElseThrow(() -> new AssertionError("El rol ASESOR deberia estar sembrado"));

        UUID correo = UUID.randomUUID();
        User saved = withTenantContext(() -> userRepositoryPort.save(User.create(
                new TenantId(TENANT_ID),
                Email.of("mecanico-" + correo + "@driveos.pe"),
                PasswordHash.of("hash-de-prueba"),
                "Juan Perez",
                Set.of(asesor))));

        // La tabla intermedia lleva su propio tenant_id, que NO puede
        // representarse con un @JoinTable de dos columnas. Sin el, el
        // INSERT viola la restriccion NOT NULL.
        //
        // La lectura se hace con el propietario: el rol de aplicacion esta
        // sujeto a la politica de aislamiento, y sin el contexto de taller
        // la fila no seria visible.
        try (var connection = EmbeddedPostgresSupport.openOwnerConnection();
             var statement = connection.createStatement();
             var rs = statement.executeQuery(
                     "SELECT count(*) FROM user_roles WHERE user_id = '" + saved.getId()
                             + "' AND tenant_id = '" + TENANT_ID + "'")) {
            rs.next();
            assertEquals(1, rs.getInt(1),
                    "La fila de la tabla intermedia debe llevar el taller del usuario");
        }
    }

    @Test
    void elAltaDeUnUsuarioConRolesPersisteLaAsignacion() {
        Role asesor = roleRepositoryPort.findByCode(RoleCode.ASESOR)
                .orElseThrow(() -> new AssertionError("El rol ASESOR deberia estar sembrado"));

        User saved = withTenantContext(() -> userRepositoryPort.save(User.create(
                new TenantId(TENANT_ID),
                Email.of("mecanico@driveos.pe"),
                PasswordHash.of("hash-de-prueba"),
                "Juan Perez",
                Set.of(asesor))));

        assertNotNull(saved.getId());
        assertEquals(1, saved.getRoles().size(), "El usuario debe tener un rol asignado");
        assertEquals(RoleCode.ASESOR, saved.getRoles().iterator().next().getCode());
        assertEquals(TENANT_ID, saved.getTenantId().getValue());
    }

    @Test
    void sinContextoDeTenantLaEscrituraEsRechazada() {
        Role asesor = roleRepositoryPort.findByCode(RoleCode.ASESOR)
                .orElseThrow(() -> new AssertionError("El rol ASESOR deberia estar sembrado"));

        User usuario = User.create(
                new TenantId(TENANT_ID),
                Email.of("mecanico3@driveos.pe"),
                PasswordHash.of("hash-de-prueba"),
                "Carlos Ruiz",
                Set.of(asesor));

        org.junit.jupiter.api.Assertions.assertThrows(RuntimeException.class,
                () -> userRepositoryPort.save(usuario),
                "Sin contexto de tenant la escritura debe rechazarse");
    }

    @Test
    void laAsignacionDeRolQuedaVinculadaAlTenantDelUsuario() throws Exception {
        Role asesor = roleRepositoryPort.findByCode(RoleCode.ASESOR)
                .orElseThrow(() -> new AssertionError("El rol ASESOR deberia estar sembrado"));

        User user = User.create(
                new TenantId(TENANT_ID),
                Email.of("mecanico2@driveos.pe"),
                PasswordHash.of("hash-de-prueba"),
                "Maria Lopez",
                Set.of(asesor));

        withTenantContext(() -> userRepositoryPort.save(user));

        try (var connection = EmbeddedPostgresSupport.openOwnerConnection();
             var statement = connection.createStatement();
             var rs = statement.executeQuery(
                     "SELECT tenant_id, role_id FROM user_roles WHERE user_id = '" + user.getId() + "'")) {
            assertTrue(rs.next(), "Debe existir una asignacion de rol para el usuario");
            assertEquals(TENANT_ID, rs.getObject("tenant_id", UUID.class),
                    "La asignacion de rol debe llevar el tenant del usuario");
            assertEquals(asesor.getId(), rs.getObject("role_id", UUID.class),
                    "La asignacion de rol debe llevar el rol correcto");
        }
    }

    /**
     * El contexto de taller se establece por el mismo camino que en
     * produccion: el ambito de contexto, que ademas fija el valor de sesion
     * que consume el aspecto de Row-Level Security.
     */
    private <T> T withTenantContext(java.util.function.Supplier<T> operation) {
        try (var scope = com.erp.auth.infrastructure.persistence.rls.TenantContextScope.forTenant(TENANT_ID)) {
            TransactionTemplate template = new TransactionTemplate(transactionManager);
            return template.execute(status -> {
                jdbcTemplate.execute("SET LOCAL app.tenant_id = '" + TENANT_ID + "'");
                return operation.get();
            });
        }
    }
}
