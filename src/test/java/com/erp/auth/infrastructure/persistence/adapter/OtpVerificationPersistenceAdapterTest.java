package com.erp.auth.infrastructure.persistence.adapter;

import com.erp.auth.domain.model.OtpPurpose;
import com.erp.auth.domain.model.OtpVerification;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.domain.valueobject.OtpCodeHash;
import com.erp.auth.domain.valueobject.OtpVerificationId;
import com.erp.auth.infrastructure.persistence.TransactionGuard;
import com.erp.auth.infrastructure.persistence.entity.OtpVerificationJpaEntity;
import com.erp.auth.infrastructure.persistence.repository.SpringDataOtpVerificationRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Duration;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("Infrastructure - OtpVerificationPersistenceAdapter Test")
class OtpVerificationPersistenceAdapterTest {

    @Mock
    private SpringDataOtpVerificationRepository repository;

    @Mock
    private TransactionGuard transactionGuard;

    private OtpVerificationPersistenceAdapter adapter;

    @BeforeEach
    void setUp() {
        adapter = new OtpVerificationPersistenceAdapter(repository, transactionGuard);
    }

    @Test
    @DisplayName("Should enforce transaction and save mapped entity")
    void shouldSaveOtpVerification() {
        Email email = new Email("test@domain.com");
        OtpCodeHash hash = new OtpCodeHash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        OtpVerification domain = OtpVerification.create(null, null, email, OtpPurpose.EMAIL_VERIFICATION, hash, Duration.ofMinutes(10), Clock.systemUTC());

        when(repository.save(any(OtpVerificationJpaEntity.class))).thenAnswer(invocation -> invocation.getArgument(0));

        OtpVerification result = adapter.save(domain);

        verify(transactionGuard).requireActiveTransaction("saveOtpVerification");
        assertThat(result).isNotNull();
        assertThat(result.getEmail()).isEqualTo(email);
    }

    @Test
    @DisplayName("Should call incrementAttempts with active transaction check")
    void shouldIncrementAttempts() {
        OtpVerificationId id = OtpVerificationId.generate();

        adapter.incrementAttempts(id);

        verify(transactionGuard).requireActiveTransaction("incrementAttempts");
        verify(repository).incrementAttempts(id.value());
    }

    @Test
    @DisplayName("Should call invalidateAllPendingByEmail with active transaction check")
    void shouldInvalidateAllPendingByEmail() {
        Email email = new Email("test@domain.com");

        adapter.invalidateAllPendingByEmail(email);

        verify(transactionGuard).requireActiveTransaction("invalidateAllPendingByEmail");
        verify(repository).invalidateAllPendingByEmail(email.value());
    }
}
