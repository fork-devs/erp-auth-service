package com.erp.auth.support;

import com.erp.auth.domain.model.Role;
import com.erp.auth.domain.model.RoleCode;
import com.erp.auth.domain.model.User;
import com.erp.auth.domain.port.PasswordEncoderPort;
import com.erp.auth.domain.port.PasswordResetTokenRepositoryPort;
import com.erp.auth.domain.port.RefreshTokenRepositoryPort;
import com.erp.auth.domain.port.RoleRepositoryPort;
import com.erp.auth.domain.port.TokenSignerPort;
import com.erp.auth.domain.port.UnitOfWork;
import com.erp.auth.domain.port.UserRepositoryPort;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.domain.valueobject.PasswordHash;
import com.erp.auth.domain.valueobject.TenantId;
import com.erp.auth.infrastructure.persistence.entity.RefreshTokenJpaEntity;
import com.erp.auth.infrastructure.persistence.entity.UserJpaEntity;
import com.erp.auth.infrastructure.persistence.rls.TenantContextHolder;
import com.erp.auth.infrastructure.persistence.rls.TenantContextScope;
import com.erp.auth.infrastructure.persistence.repository.SpringDataRefreshTokenRepository;
import com.erp.auth.infrastructure.persistence.repository.SpringDataUserRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

import java.util.Set;
import java.util.UUID;

/**
 * Base de los tests de atomicidad de las operaciones de autenticacion.
 *
 * <p>Cada operacion escribe en mas de un almacen: rotar un token revoca el
 * anterior y crea el nuevo; restablecer una contrasena consume el token,
 * cambia la clave y revoca las sesiones; iniciar sesion restablece el
 * contador de intentos y emite el token. Sin un limite transaccional comun,
 * un fallo entre esas escrituras deja al usuario en un estado que el sistema
 * no puede recuperar: sin sesion, con el token consumido y la contrasena sin
 * cambiar.
 *
 * <p>Ver docs/doc-estado-implementacion.md, hallazgo P0 5.3.
 */
abstract class AbstractAuthAtomicityTest extends AbstractPostgresIntegrationTest {

    protected static final UUID TALLER = UUID.fromString("cccc1111-3333-4444-5555-666677778888");
    protected static final String CONTRASENA = "ContrasenaLarga1!";

    @Autowired
    protected UserRepositoryPort userRepositoryPort;

    @Autowired
    protected RefreshTokenRepositoryPort refreshTokenRepositoryPort;

    @Autowired
    protected PasswordResetTokenRepositoryPort passwordResetTokenRepositoryPort;

    @Autowired
    protected RoleRepositoryPort roleRepositoryPort;

    @Autowired
    protected UnitOfWork unitOfWork;

    @Autowired
    protected TokenSignerPort tokenSignerPort;

    @Autowired
    protected PasswordEncoderPort passwordEncoderPort;

    /**
     * Se espian los repositorios de Spring Data, y no los puertos: el punto
     * de corte del aspecto de aislamiento cubre los adaptadores, de modo que
     * espiar un puerto exigiria un contexto de taller para la propia
     * operacion de espiado.
     */
    @MockitoSpyBean
    protected SpringDataRefreshTokenRepository springDataRefreshTokenRepository;

    @MockitoSpyBean
    protected SpringDataUserRepository springDataUserRepository;

    /**
     * El correo es unico en toda la base, de modo que cada test necesita el
     * suyo: si no, el segundo test chocaria con el usuario del primero.
     */
    protected String correo;

    @BeforeEach
    void prepararUsuario() {
        correo = "atomico-" + UUID.randomUUID() + "@taller.pe";

        // El rol se toma del catalogo sembrado: la escritura de la asignacion
        // referencia la fila real, no una copia desatendida.
        Role admin = roleRepositoryPort.findByCode(RoleCode.ADMIN_TALLER)
                .orElseThrow(() -> new AssertionError("El rol ADMIN_TALLER deberia estar sembrado"));
        User user = User.create(
                new TenantId(TALLER),
                Email.of(correo),
                PasswordHash.of(passwordEncoderPort.encode(CONTRASENA)),
                "Usuario Atomico",
                Set.of(admin));

        try (TenantContextScope scope = TenantContextScope.forTenant(TALLER)) {
            unitOfWork.runInTransaction(() -> userRepositoryPort.save(user));
        }
    }

    @AfterEach
    void limpiarContexto() {
        TenantContextHolder.clear();
    }

    protected User usuario() {
        try (TenantContextScope scope = TenantContextScope.forTenant(TALLER)) {
            return userRepositoryPort.findByEmailAndTenantId(Email.of(correo), new TenantId(TALLER)).orElseThrow();
        }
    }

    protected void falloAlEscribirElToken(Throwable error) {
        org.mockito.Mockito.doThrow(error)
                .when(springDataRefreshTokenRepository)
                .save(any(RefreshTokenJpaEntity.class));
    }

    protected void falloAlEscribirElUsuario(Throwable error) {
        org.mockito.Mockito.doThrow(error)
                .when(springDataUserRepository)
                .save(any(UserJpaEntity.class));
    }

    private static <T> T any(Class<T> tipo) {
        return org.mockito.ArgumentMatchers.any(tipo);
    }
}
