package com.erp.auth.domain;

import com.erp.auth.domain.valueobject.TenantId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Domain - TenantId Value Object Test")
class TenantIdTest {

    private static final String NIL_UUID_STRING = "00000000-0000-0000-0000-000000000000";
    private static final UUID NIL_UUID = new UUID(0L, 0L);

    @Test
    @DisplayName("Should create TenantId with valid UUID")
    void shouldCreateTenantIdWithValidUuid() {
        UUID raw = UUID.randomUUID();
        TenantId tenantId = new TenantId(raw);

        assertNotNull(tenantId);
        assertEquals(raw, tenantId.value());
        assertEquals(raw.toString(), tenantId.toString());
    }

    @Test
    @DisplayName("Should throw IllegalArgumentException when UUID is null")
    void shouldThrowWhenUuidIsNull() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> new TenantId(null));
        assertTrue(ex.getMessage().contains("cannot be null"));
    }

    @Test
    @DisplayName("Should throw IllegalArgumentException when UUID is nil (00000000-0000-0000-0000-000000000000)")
    void shouldThrowWhenUuidIsNil() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> new TenantId(NIL_UUID));
        assertTrue(ex.getMessage().contains("nil UUID"));
    }

    @Test
    @DisplayName("Should create TenantId from valid UUID string with trimming")
    void shouldCreateTenantIdFromValidString() {
        UUID raw = UUID.randomUUID();
        TenantId tenantId = TenantId.fromString("  " + raw.toString() + "  ");

        assertEquals(raw, tenantId.value());
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t", "\n"})
    @DisplayName("Should throw IllegalArgumentException when fromString receives null or blank")
    void shouldThrowWhenFromStringReceivesBlank(String invalid) {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> TenantId.fromString(invalid));
        assertTrue(ex.getMessage().contains("cannot be blank"));
    }

    @Test
    @DisplayName("Should throw IllegalArgumentException when fromString receives nil UUID")
    void shouldThrowWhenFromStringReceivesNilUuid() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> TenantId.fromString(NIL_UUID_STRING));
        assertTrue(ex.getMessage().contains("nil UUID"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"invalid-uuid", "12345", "not-a-uuid-format"})
    @DisplayName("Should throw contextual IllegalArgumentException when UUID format is malformed")
    void shouldThrowContextualExceptionOnMalformedUuid(String malformed) {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> TenantId.fromString(malformed));
        assertTrue(ex.getMessage().contains("Invalid TenantId format: " + malformed));
        assertNotNull(ex.getCause());
    }

    @Test
    @DisplayName("Should generate valid non-nil TenantId")
    void shouldGenerateValidTenantId() {
        TenantId generated1 = TenantId.generate();
        TenantId generated2 = TenantId.generate();

        assertNotNull(generated1);
        assertNotNull(generated2);
        assertNotEquals(generated1, generated2);
        assertNotEquals(NIL_UUID, generated1.value());
    }

    @Test
    @DisplayName("Should satisfy equality contract based on UUID value")
    void shouldSatisfyEqualityContract() {
        UUID raw = UUID.randomUUID();
        TenantId id1 = new TenantId(raw);
        TenantId id2 = new TenantId(raw);

        assertEquals(id1, id2);
        assertEquals(id1.hashCode(), id2.hashCode());
    }

    @Test
    @DisplayName("Should be serializable with valid serialVersionUID")
    void shouldBeSerializable() throws Exception {
        TenantId original = TenantId.generate();

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(original);
        }

        TenantId deserialized;
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(baos.toByteArray()))) {
            deserialized = (TenantId) ois.readObject();
        }

        assertEquals(original, deserialized);
    }
}
