package com.erp.auth.support;

import com.erp.auth.domain.model.Role;
import com.erp.auth.domain.model.RoleCode;
import com.erp.auth.domain.model.User;
import com.erp.auth.domain.port.RoleRepositoryPort;
import com.erp.auth.domain.port.SecondFactorRepositoryPort;
import com.erp.auth.domain.port.UserRepositoryPort;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.domain.valueobject.PasswordHash;
import com.erp.auth.domain.valueobject.TenantId;
import com.erp.auth.infrastructure.persistence.rls.TenantContextScope;
import com.erp.auth.infrastructure.security.crypto.SecretCipher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * El secreto del segundo factor se guarda cifrado, y los codigos de
 * recuperacion son de un solo uso.
 *
 * <p>Un secreto TOTP se verifica a partir del material compartido: quien lo
 * lea puede generar codigos validos. Un codigo de recuperacion es una
 * credencial: se guarda su hash, y se invalida en el momento del uso.
 *
 * <p>Ver docs/doc-estado-implementacion.md, hallazgos P1 6.18.
 */
class SecondFactorPersistenceTest extends AbstractPostgresIntegrationTest {

    private static final UUID TALLER = UUID.fromString("ffff1111-2222-3333-4444-555555555555");
    private static final String SECRETO = "JBSWY3DPEHPK3PXP";
    private static final String HASH = "hash-del-codigo-de-recuperacion";

    @Autowired
    private SecondFactorRepositoryPort secondFactorRepositoryPort;

    @Autowired
    private SecretCipher secretCipher;

    @Autowired
    private com.erp.auth.domain.port.UnitOfWork unitOfWork;

    @Autowired
    private UserRepositoryPort userRepositoryPort;

    @Autowired
    private RoleRepositoryPort roleRepositoryPort;

    private UUID userId;

    /**
     * La operacion, dentro del contexto de taller y de una transaccion: es
     * lo que hace la aplicacion en produccion.
     */
    private <T> T enTransaccion(java.util.function.Supplier<T> operacion) {
        try (TenantContextScope scope = TenantContextScope.forTenant(TALLER)) {
            return unitOfWork.callInTransaction(operacion);
        }
    }

    private void enTransaccion(Runnable operacion) {
        try (TenantContextScope scope = TenantContextScope.forTenant(TALLER)) {
            unitOfWork.runInTransaction(operacion);
        }
    }

    @BeforeEach
    void setUp() {
        // El segundo factor pertenece a un usuario: la clave foranea lo
        // exige, y una fila huerfana no seria representativa.
        Role admin = roleRepositoryPort.findByCode(RoleCode.ADMIN_TALLER)
                .orElseThrow(() -> new AssertionError("El rol ADMIN_TALLER deberia estar sembrado"));
        User user = User.create(
                new TenantId(TALLER),
                Email.of("mfa-" + UUID.randomUUID() + "@taller.pe"),
                PasswordHash.of("$2a$12$hash"),
                "Usuario",
                Set.of(admin));

        try (TenantContextScope scope = TenantContextScope.forTenant(TALLER)) {
            unitOfWork.runInTransaction(() -> userRepositoryPort.save(user));
        }
        userId = user.getId();
    }

    @Test
    @DisplayName("El secreto se guarda cifrado: una lectura directa de la tabla no muestra el valor en claro")
    void elSecretoSeGuardaCifrado() throws Exception {
        String cifrado = secretCipher.encrypt(SECRETO);

        enTransaccion(() -> secondFactorRepositoryPort.storeSecret(userId, cifrado));

        // Lectura directa de la tabla, como el propietario.
        try (var connection = EmbeddedPostgresSupport.openOwnerConnection();
             var statement = connection.createStatement();
             var rs = statement.executeQuery(
                     "SELECT mfa_secret_ciphertext FROM users WHERE id = '" + userId + "'")) {
            assertTrue(rs.next(), "El usuario debe existir");
            String valorEnLaTabla = rs.getString(1);
            assertNotEquals(SECRETO, valorEnLaTabla,
                    "El secreto no puede estar en claro en la tabla");
            assertFalse(valorEnLaTabla.contains(SECRETO));
            assertEquals(SECRETO, secretCipher.decrypt(valorEnLaTabla),
                    "Lo que hay en la tabla debe poder descifrarse al secreto");
        }
    }

    @Test
    @DisplayName("El cifrado no produce el mismo texto dos veces")
    void elCifradoNoProduceElMismoTextoDosVeces() {
        String primero = secretCipher.encrypt(SECRETO);
        String segundo = secretCipher.encrypt(SECRETO);

        assertNotEquals(primero, segundo,
                "Si el cifrado fuera determinista, dos secretos iguales darian el mismo texto, y eso "
                        + "permitiria comparar textos cifrados para adivinar el secreto");
        assertEquals(SECRETO, secretCipher.decrypt(primero));
        assertEquals(SECRETO, secretCipher.decrypt(segundo));
    }

    @Test
    @DisplayName("Un codigo de recuperacion se acepta una vez y se rechaza en el segundo uso")
    void unCodigoDeRecuperacionSeAceptaUnaVez() {
        Instant caducidad = Instant.now().plusSeconds(3600);

        enTransaccion(() ->
                secondFactorRepositoryPort.storeRecoveryCodes(userId, List.of(HASH), caducidad));

        assertTrue(enTransaccion(() -> secondFactorRepositoryPort.consumeRecoveryCode(userId, HASH)).isPresent(),
                "El primer uso del codigo debe aceptarse");
        assertFalse(enTransaccion(() -> secondFactorRepositoryPort.consumeRecoveryCode(userId, HASH)).isPresent(),
                "El segundo uso del codigo debe rechazarse: es de un solo uso");
    }

    @Test
    @DisplayName("Un codigo de recuperacion caducado no se acepta")
    void unCodigoDeRecuperacionCaducadoNoSeAcepta() {
        enTransaccion(() -> secondFactorRepositoryPort.storeRecoveryCodes(
                userId, List.of("hash-caducado"), Instant.now().minusSeconds(60)));

        assertFalse(enTransaccion(() -> secondFactorRepositoryPort.consumeRecoveryCode(userId, "hash-caducado"))
                .isPresent(), "Un codigo caducado no puede usarse");
    }
}
