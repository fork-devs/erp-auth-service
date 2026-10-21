package com.erp.auth.support;

import com.erp.auth.application.dto.command.RegisterUserCommand;
import com.erp.auth.application.service.RegisterUserService;
import com.erp.auth.domain.model.Role;
import com.erp.auth.domain.model.RoleCode;
import com.erp.auth.domain.model.User;
import com.erp.auth.domain.port.RoleRepositoryPort;
import com.erp.auth.domain.port.UserRepositoryPort;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.domain.valueobject.PasswordHash;
import com.erp.auth.domain.valueobject.TenantId;
import com.erp.auth.infrastructure.persistence.rls.TenantContextScope;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * La identidad de la cuenta queda acotada al taller.
 *
 * <p>El correo era UNIQUE global: una sola cuenta podia existir en toda la
 * plataforma. Eso impedia registrar a un empleado con el mismo correo que
 * tiene en otro taller, y el conflicto de unicidad permitia enumerar las
 * cuentas ajenas.
 *
 * <p>Ver docs/doc-estado-implementacion.md, hallazgo P1 6.22.
 */
class EmailUniquenessPerTenantTest extends AbstractPostgresIntegrationTest {

    private static final UUID TALLER_A = UUID.fromString("bbbb1111-2222-3333-4444-555555555555");
    private static final UUID TALLER_B = UUID.fromString("cccc1111-2222-3333-4444-555555555555");

    @Autowired
    private UserRepositoryPort userRepositoryPort;

    @Autowired
    private RoleRepositoryPort roleRepositoryPort;

    @Autowired
    private com.erp.auth.domain.port.UnitOfWork unitOfWork;

    @Test
    @DisplayName("El mismo correo puede registrarse en dos talleres distintos")
    void elMismoCorreoPuedeRegistrarseEnDosTalleres() {
        String correo = "compartido-" + UUID.randomUUID() + "@taller.pe";

        crearUsuario(correo, TALLER_A);
        crearUsuario(correo, TALLER_B);

        assertEquals(2, usuariosConCorreo(correo).size(),
                "El mismo correo puede existir en dos talleres distintos");
    }

    @Test
    @DisplayName("En un mismo taller, el correo repetido se rechaza")
    void enUnMismoTallerElCorreoRepetidoSeRechaza() {
        String correo = "repetido-" + UUID.randomUUID() + "@taller.pe";
        crearUsuario(correo, TALLER_A);

        assertThrows(RuntimeException.class, () -> crearUsuario(correo, TALLER_A),
                "Dos cuentas con el mismo correo en el mismo taller no pueden existir");
    }

    @Test
    @DisplayName("El indice unico es por taller, no global")
    void elIndiceUnicoEsPorTaller() throws Exception {
        try (var connection = EmbeddedPostgresSupport.openOwnerConnection();
             var statement = connection.createStatement();
             var rs = statement.executeQuery(
                     "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                     + "WHERE n.nspname = 'public' AND c.relname = 'uk_users_tenant_email'")) {
            rs.next();
            assertEquals(1, rs.getInt(1), "Debe existir el indice unico por taller");
        }

        try (var connection = EmbeddedPostgresSupport.openOwnerConnection();
             var statement = connection.createStatement();
             var rs = statement.executeQuery(
                     "SELECT count(*) FROM pg_constraint c JOIN pg_class t ON t.oid = c.conrelid "
                     + "WHERE t.relname = 'users' AND c.contype = 'u' AND c.conname = 'users_email_key'")) {
            rs.next();
            assertEquals(0, rs.getInt(1), "La unicidad global del correo debe haberse retirado");
        }
    }

    @Test
    @DisplayName("La respuesta del registro no distingue el correo existente en otro taller")
    void laRespuestaNoDistingueElCorreoDeOtroTaller() {
        RegisterUserService servicio = servicioDeRegistro();
        String correo = "ajeno-" + UUID.randomUUID() + "@taller.pe";

        // El correo ya existe en OTRO taller.
        crearUsuario(correo, TALLER_B);

        // En el taller propio, el correo esta libre: el registro debe
        // funcionar, y no debe insinuar que el correo existe en otro sitio.
        assertDoesNotThrow(() -> {
            try (TenantContextScope scope = TenantContextScope.forTenant(TALLER_A)) {
                servicio.register(new RegisterUserCommand(
                        new TenantId(TALLER_A),
                        correo,
                        "ContrasenaLarga1!",
                        "Usuario",
                        java.util.EnumSet.of(RoleCode.MECANICO),
                        RoleCode.ADMIN_TALLER));
            }
        }, "El correo libre en este taller debe poder registrarse aunque exista en otro");
    }

    private RegisterUserService servicioDeRegistro() {
        return new RegisterUserService(
                userRepositoryPort,
                roleRepositoryPort,
                new com.erp.auth.infrastructure.security.crypto.BCryptPasswordEncoderAdapter(12),
                new com.erp.auth.domain.model.PasswordPolicy(14),
                unitOfWork);
    }

    private void crearUsuario(String correo, UUID taller) {
        Role asesor = roleRepositoryPort.findByCode(RoleCode.ASESOR)
                .orElseThrow(() -> new AssertionError("El rol ASESOR deberia estar sembrado"));
        User user = User.create(
                new TenantId(taller),
                Email.of(correo),
                PasswordHash.of("$2a$12$hash"),
                "Usuario",
                Set.of(asesor));

        try (TenantContextScope scope = TenantContextScope.forTenant(taller)) {
            unitOfWork.runInTransaction(() -> userRepositoryPort.save(user));
        }
    }

    private java.util.List<User> usuariosConCorreo(String correo) {
        java.util.List<User> usuarios = new java.util.ArrayList<>();
        for (UUID taller : new UUID[]{TALLER_A, TALLER_B}) {
            try (TenantContextScope scope = TenantContextScope.forTenant(taller)) {
                userRepositoryPort.findByEmailAndTenantId(Email.of(correo), new TenantId(taller))
                        .ifPresent(usuarios::add);
            }
        }
        return usuarios;
    }
}
