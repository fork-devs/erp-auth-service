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
 * Base test suite for transaction atomicity of authentication operations.
 *
 * <p>Authentication operations span multiple repositories: token rotation revokes
 * previous tokens and creates new ones; password reset consumes tokens, updates hashes,
 * and revokes active sessions; login resets attempt counters and issues tokens.
 * Without unified transaction boundaries, partial failures cause unrecoverable state.
 *
 * <p>See docs/doc-estado-implementacion.md, finding P0 5.3.
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
     * Spring Data repositories are spied directly rather than domain ports:
     * the tenant RLS aspect pointcut targets adapters, so spying a port would
     * require tenant context for the verification invocation itself.
     */
    @MockitoSpyBean
    protected SpringDataRefreshTokenRepository springDataRefreshTokenRepository;

    @MockitoSpyBean
    protected SpringDataUserRepository springDataUserRepository;

    /**
     * Generates a unique email per test execution to prevent cross-test collisions.
     */
    protected String correo;

    @BeforeEach
    void prepararUsuario() {
        correo = "atomico-" + UUID.randomUUID() + "@taller.pe";

        // Role is resolved from seeded catalog so the assignment references a managed row.
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
