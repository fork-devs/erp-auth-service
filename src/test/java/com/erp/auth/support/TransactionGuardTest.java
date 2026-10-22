package com.erp.auth.support;

import com.erp.auth.domain.model.User;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.domain.valueobject.PasswordHash;
import com.erp.auth.domain.valueobject.TenantId;
import com.erp.auth.infrastructure.persistence.MissingTransactionBoundaryException;
import com.erp.auth.infrastructure.persistence.TransactionGuard;
import com.erp.auth.infrastructure.persistence.adapter.UserPersistenceAdapter;
import com.erp.auth.infrastructure.persistence.repository.SpringDataRoleRepository;
import com.erp.auth.infrastructure.persistence.repository.SpringDataUserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

/**
 * Los adaptadores de escritura se unen a la transaccion en curso: no abren
 * una propia.
 *
 * <p>Invocarlos fuera de un limite transaccional falla de forma explicita,
 * en lugar de confirmar la escritura en una transaccion implicita que
 * romperia la atomicidad que el caso de uso pretendia.
 *
 * <p>Ver docs/doc-estado-implementacion.md, hallazgos P0 5.3 y P0 5.8.
 */
class TransactionGuardTest {

    private UserPersistenceAdapter adapter;

    @BeforeEach
    void setUp() {
        adapter = new UserPersistenceAdapter(
                mock(SpringDataUserRepository.class),
                mock(SpringDataRoleRepository.class),
                new TransactionGuard());
    }

    @Test
    void guardarFueraDeUnLimiteTransaccionalFallaDeFormaExplicita() {
        MissingTransactionBoundaryException excepcion = assertThrows(
                MissingTransactionBoundaryException.class,
                () -> adapter.save(usuario()));

        assertTrue(excepcion.getMessage().contains("saveUser"),
                "El mensaje debe identificar la operacion que falta de demarcacion: " + excepcion.getMessage());
        assertTrue(excepcion.getMessage().contains("limite transaccional"),
                "El mensaje debe identificar la ausencia de demarcacion: " + excepcion.getMessage());
    }

    @Test
    void borrarFueraDeUnLimiteTransaccionalFallaDeFormaExplicita() {
        MissingTransactionBoundaryException excepcion = assertThrows(
                MissingTransactionBoundaryException.class,
                () -> adapter.deleteById(UUID.randomUUID()));

        assertTrue(excepcion.getMessage().contains("deleteUser"));
    }

    private User usuario() {
        return User.create(
                TenantId.generate(),
                Email.of("guarda@taller.pe"),
                PasswordHash.of("$2a$12$hash"),
                "Usuario",
                Set.of());
    }
}
