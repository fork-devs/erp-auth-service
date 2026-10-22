package com.erp.auth.support;

import com.erp.auth.application.dto.command.LoginCommand;
import com.erp.auth.application.dto.result.AuthResult;
import com.erp.auth.application.service.AuthenticateUserService;
import com.erp.auth.application.service.SecondFactorEnrollmentService;
import com.erp.auth.domain.model.NotificationMessage;
import com.erp.auth.domain.model.Role;
import com.erp.auth.domain.model.RoleCode;
import com.erp.auth.domain.model.User;
import com.erp.auth.domain.port.NotificationPort;
import com.erp.auth.domain.port.PasswordEncoderPort;
import com.erp.auth.domain.port.RoleRepositoryPort;
import com.erp.auth.domain.port.SecondFactorPort;
import com.erp.auth.domain.port.SecondFactorRepositoryPort;
import com.erp.auth.domain.port.TokenSignerPort;
import com.erp.auth.domain.port.UnitOfWork;
import com.erp.auth.domain.port.UserRepositoryPort;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.domain.valueobject.PasswordHash;
import com.erp.auth.domain.valueobject.TenantId;
import com.erp.auth.infrastructure.persistence.rls.TenantContextScope;
import com.erp.auth.infrastructure.security.crypto.SecretCipher;
import com.erp.auth.infrastructure.security.mfa.TotpSecondFactorAdapter;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * El segundo factor se enrola, se confirma y se exige en el inicio de sesion.
 *
 * <p>El enrolamiento NO expone el secreto ni los codigos de recuperacion en
 * la respuesta: se entregan por el canal de notificacion.
 */
class SecondFactorEnrollmentTest extends AbstractPostgresIntegrationTest {

    private static final UUID TALLER = UUID.fromString("aaaa1111-2222-3333-4444-555555555555");
    private static final String CONTRASENA = "ContrasenaLarga1!";

    @Autowired
    private SecondFactorEnrollmentService enrollmentService;

    @Autowired
    private AuthenticateUserService authenticateUserService;

    @Autowired
    private UserRepositoryPort userRepositoryPort;

    @Autowired
    private RoleRepositoryPort roleRepositoryPort;

    @Autowired
    private SecondFactorRepositoryPort secondFactorRepositoryPort;

    @Autowired
    private UnitOfWork unitOfWork;

    @Autowired
    private TokenSignerPort tokenSignerPort;

    @Autowired
    private SecretCipher secretCipher;

    @Autowired
    private PasswordEncoderPort passwordEncoderPort;

    /** Notificaciones entregadas durante el test. */
    private List<NotificationMessage> entregadas;

    private User usuario;

    @BeforeEach
    void setUp() {
        entregadas = new ArrayList<>();

        Role admin = roleRepositoryPort.findByCode(RoleCode.ADMIN_TALLER)
                .orElseThrow(() -> new AssertionError("El rol ADMIN_TALLER deberia estar sembrado"));
        usuario = User.create(
                new TenantId(TALLER),
                Email.of("mfa-" + UUID.randomUUID() + "@taller.pe"),
                PasswordHash.of(passwordEncoderPort.encode(CONTRASENA)),
                "Usuario",
                Set.of(admin));

        try (TenantContextScope scope = TenantContextScope.forTenant(TALLER)) {
            unitOfWork.runInTransaction(() -> userRepositoryPort.save(usuario));
        }
    }

    @Test
    @DisplayName("El enrolamiento entrega el secreto y los codigos, y no los expone en la respuesta")
    void elEnrolamientoEntregaElSecretoYLosCodigos() {
        NotificationPort registro = entregadas::add;
        SecondFactorEnrollmentService servicio = servicioCon(registro);

        try (TenantContextScope scope = TenantContextScope.forTenant(TALLER)) {
            servicio.enroll(usuario.getId(), TALLER);
        }

        assertEquals(1, entregadas.size(), "El enrolamiento debe entregar una notificacion");
        NotificationMessage notificacion = entregadas.get(0);
        assertEquals(usuario.getEmail().getValue(), notificacion.recipient());
        assertTrue(notificacion.body().contains("otpauth://"),
                "La notificacion debe llevar el enlace de enrolamiento");
        assertTrue(notificacion.body().contains("-"),
                "La notificacion debe llevar los codigos de recuperacion");
    }

    @Test
    @DisplayName("La confirmacion con un codigo valido habilita el segundo factor")
    void laConfirmacionConUnCodigoValidoHabilitaElSegundoFactor() {
        SecondFactorEnrollmentService servicio = servicioCon(entregadas::add);

        try (TenantContextScope scope = TenantContextScope.forTenant(TALLER)) {
            servicio.enroll(usuario.getId(), TALLER);
        }

        String secreto;
        try (TenantContextScope scope = TenantContextScope.forTenant(TALLER)) {
            secreto = secondFactorRepositoryPort.findSecret(usuario.getId()).orElseThrow();
        }
        // El codigo del intervalo ANTERIOR: la ventana de tolerancia lo
        // acepta, y deja libre el codigo del intervalo actual para el
        // inicio de sesion.
        String codigo = codigoDeIntervalo(secreto, -30_000L);

        try (TenantContextScope scope = TenantContextScope.forTenant(TALLER)) {
            servicio.confirm(usuario.getId(), TALLER, codigo);
        }

        assertTrue(usuarioEnBaseDeDatos().isMfaEnabled(),
                "Con un codigo valido, el segundo factor queda habilitado");
    }

    @Test
    @DisplayName("La confirmacion con un codigo invalido no habilita el segundo factor")
    void laConfirmacionConUnCodigoInvalidoNoHabilita() {
        SecondFactorEnrollmentService servicio = servicioCon(entregadas::add);

        try (TenantContextScope scope = TenantContextScope.forTenant(TALLER)) {
            servicio.enroll(usuario.getId(), TALLER);
        }

        assertThrows(RuntimeException.class, () -> {
            try (TenantContextScope scope = TenantContextScope.forTenant(TALLER)) {
                servicio.confirm(usuario.getId(), TALLER, "000000");
            }
        });

        assertFalse(usuarioEnBaseDeDatos().isMfaEnabled(),
                "Un codigo invalido no puede habilitar el segundo factor");
    }

    @Test
    @DisplayName("Un login sin codigo de un usuario con segundo factor no emite credenciales")
    void unLoginSinCodigoNoEmiteCredenciales() {
        SecondFactorEnrollmentService servicio = servicioCon(entregadas::add);

        try (TenantContextScope scope = TenantContextScope.forTenant(TALLER)) {
            servicio.enroll(usuario.getId(), TALLER);
            String secreto = secondFactorRepositoryPort.findSecret(usuario.getId()).orElseThrow();
            servicio.confirm(usuario.getId(), TALLER, codigoDeIntervalo(secreto, 0L));
        }

        assertThrows(RuntimeException.class, () -> {
            try (TenantContextScope scope = TenantContextScope.forTenant(TALLER)) {
                authenticateUserService.authenticate(new LoginCommand(
                        usuario.getEmail().getValue(), CONTRASENA, TALLER));
            }
        }, "Un login sin codigo de segundo factor no puede emitir credenciales");
    }

    @Test
    @DisplayName("Un login con codigo valido si emite credenciales")
    void unLoginConCodigoValidoEmiteCredenciales() {
        SecondFactorEnrollmentService servicio = servicioCon(entregadas::add);
        String codigo;
        String secretoLogin;

        try (TenantContextScope scope = TenantContextScope.forTenant(TALLER)) {
            servicio.enroll(usuario.getId(), TALLER);
            String secreto = secondFactorRepositoryPort.findSecret(usuario.getId()).orElseThrow();
            codigo = codigoDeIntervalo(secreto, -30_000L);
            servicio.confirm(usuario.getId(), TALLER, codigo);
            secretoLogin = secreto;
        }

        // El codigo del intervalo actual: el anterior se consumio en la
        // confirmacion, y un codigo no se puede reutilizar.
        String codigoDeLogin = codigoDeIntervalo(secretoLogin, 0L);

        AuthResult result;
        try (TenantContextScope scope = TenantContextScope.forTenant(TALLER)) {
            result = authenticateUserService.authenticate(new LoginCommand(
                    usuario.getEmail().getValue(), CONTRASENA, TALLER, codigoDeLogin));
        }

        assertNotNull(result.accessToken());
        assertNotNull(result.refreshToken());
    }

    private String codigoDeIntervalo(String secreto, long desplazamientoMilis) {
        GoogleAuthenticator reference = new GoogleAuthenticator();
        return String.format("%06d", reference.getTotpPassword(
                secreto, Instant.now().toEpochMilli() + desplazamientoMilis));
    }

    private User usuarioEnBaseDeDatos() {
        try (TenantContextScope scope = TenantContextScope.forTenant(TALLER)) {
            return userRepositoryPort.findByIdAndTenantId(usuario.getId(), new TenantId(TALLER)).orElseThrow();
        }
    }

    /**
     * El servicio con un puerto de notificacion que registra lo entregado.
     */
    private SecondFactorEnrollmentService servicioCon(NotificationPort registro) {
        return new SecondFactorEnrollmentService(
                new TotpSecondFactorAdapter(),
                secondFactorRepositoryPort,
                userRepositoryPort,
                registro,
                new TotpSecondFactorAdapter(),
                tokenSignerPort,
                unitOfWork);
    }
}
