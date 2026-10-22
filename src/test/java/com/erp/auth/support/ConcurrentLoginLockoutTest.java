package com.erp.auth.support;

import com.erp.auth.application.dto.command.LoginCommand;
import com.erp.auth.application.service.AuthenticateUserService;
import com.erp.auth.domain.model.Role;
import com.erp.auth.domain.model.RoleCode;
import com.erp.auth.domain.model.User;
import com.erp.auth.domain.port.RoleRepositoryPort;
import com.erp.auth.domain.port.UnitOfWork;
import com.erp.auth.domain.port.UserRepositoryPort;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.domain.valueobject.PasswordHash;
import com.erp.auth.domain.valueobject.TenantId;
import com.erp.auth.infrastructure.persistence.rls.TenantContextScope;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * El bloqueo por intentos fallidos es fiable.
 *
 * <p>El contador se incrementaba con una lectura-modificacion-escritura: dos
 * intentos concurrentes leian el mismo valor y escribian el mismo incremento,
 * de modo que la cuenta se quedaba sin bloquear por muchos intentos que se
 * hicieran.
 *
 * <p>Ver docs/doc-estado-implementacion.md, hallazgo P1 6.23.
 */
class ConcurrentLoginLockoutTest extends AbstractPostgresIntegrationTest {

    private static final UUID TALLER = UUID.fromString("cccc2222-3333-4444-5555-666677778888");
    private static final String CONTRASENA = "ContrasenaLarga1!";

    @Autowired
    private AuthenticateUserService authenticateUserService;

    @Autowired
    private UserRepositoryPort userRepositoryPort;

    @Autowired
    private RoleRepositoryPort roleRepositoryPort;

    @Autowired
    private UnitOfWork unitOfWork;

    @Autowired
    private com.erp.auth.domain.port.PasswordEncoderPort passwordEncoderPort;

    private String correo;

    @BeforeEach
    void setUp() {
        correo = "concurrente-" + UUID.randomUUID() + "@taller.pe";

        Role asesor = roleRepositoryPort.findByCode(RoleCode.ASESOR)
                .orElseThrow(() -> new AssertionError("El rol ASESOR deberia estar sembrado"));
        User user = User.create(
                new TenantId(TALLER),
                Email.of(correo),
                PasswordHash.of(passwordEncoderPort.encode(CONTRASENA)),
                "Usuario",
                Set.of(asesor));

        try (TenantContextScope scope = TenantContextScope.forTenant(TALLER)) {
            unitOfWork.runInTransaction(() -> userRepositoryPort.save(user));
        }
    }

    @Test
    @DisplayName("Diez intentos fallidos concurrentes dejan el contador en diez y la cuenta bloqueada")
    void diezIntentosConcurrentesDejanElContadorEnDiez() throws Exception {
        int intentos = 10;
        ExecutorService executor = Executors.newFixedThreadPool(intentos);
        CountDownLatch todosArrancan = new CountDownLatch(1);
        List<Throwable> fallos = java.util.Collections.synchronizedList(new ArrayList<>());

        try {
            for (int i = 0; i < intentos; i++) {
                executor.submit(() -> {
                    try {
                        todosArrancan.await(5, TimeUnit.SECONDS);
                        try (TenantContextScope scope = TenantContextScope.forTenant(TALLER)) {
                            authenticateUserService.authenticate(
                                    new LoginCommand(correo, "ContrasenaEquivocada1!", TALLER));
                        }
                    } catch (Throwable t) {
                        fallos.add(t);
                    }
                });
            }
            todosArrancan.countDown();
            executor.shutdown();
            assertTrue(executor.awaitTermination(60, TimeUnit.SECONDS), "Los intentos deben terminar");
        } finally {
            executor.shutdownNow();
        }

        User despues = usuarioEnBaseDeDatos();

        assertEquals(intentos, despues.getFailedAttempts(),
                "Ningun incremento puede perderse: los diez intentos concurrentes tienen que contar");
        assertTrue(despues.isAccountLocked(),
                "Con diez intentos fallidos, la cuenta debe estar bloqueada");
    }

    private User usuarioEnBaseDeDatos() {
        try (TenantContextScope scope = TenantContextScope.forTenant(TALLER)) {
            return userRepositoryPort.findByEmailAndTenantId(Email.of(correo), new TenantId(TALLER)).orElseThrow();
        }
    }
}
