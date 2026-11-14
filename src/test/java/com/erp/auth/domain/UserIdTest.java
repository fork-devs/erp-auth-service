package com.erp.auth.domain;

import com.erp.auth.domain.valueobject.UserId;
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

@DisplayName("Domain - UserId Value Object Test")
class UserIdTest {

    private static final String NIL_UUID_STRING = "00000000-0000-0000-0000-000000000000";
    private static final UUID NIL_UUID = new UUID(0L, 0L);

    @Test
    @DisplayName("Should create UserId with valid UUID")
    void shouldCreateUserIdWithValidUuid() {
        UUID raw = UUID.randomUUID();
        UserId userId = new UserId(raw);

        assertNotNull(userId);
        assertEquals(raw, userId.value());
        assertEquals(raw.toString(), userId.toString());
    }

    @Test
    @DisplayName("Should throw IllegalArgumentException when UUID is null")
    void shouldThrowWhenUuidIsNull() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> new UserId(null));
        assertTrue(ex.getMessage().contains("cannot be null"));
    }

    @Test
    @DisplayName("Should throw IllegalArgumentException when UUID is nil (00000000-0000-0000-0000-000000000000)")
    void shouldThrowWhenUuidIsNil() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> new UserId(NIL_UUID));
        assertTrue(ex.getMessage().contains("nil UUID"));
    }

    @Test
    @DisplayName("Should create UserId from valid UUID string with trimming")
    void shouldCreateUserIdFromValidString() {
        UUID raw = UUID.randomUUID();
        UserId userId = UserId.fromString("  " + raw.toString() + "  ");

        assertEquals(raw, userId.value());
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t", "\n"})
    @DisplayName("Should throw IllegalArgumentException when fromString receives null or blank")
    void shouldThrowWhenFromStringReceivesBlank(String invalid) {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> UserId.fromString(invalid));
        assertTrue(ex.getMessage().contains("cannot be blank"));
    }

    @Test
    @DisplayName("Should throw IllegalArgumentException when fromString receives nil UUID")
    void shouldThrowWhenFromStringReceivesNilUuid() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> UserId.fromString(NIL_UUID_STRING));
        assertTrue(ex.getMessage().contains("nil UUID"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"invalid-uuid", "12345", "not-a-uuid-format"})
    @DisplayName("Should throw contextual IllegalArgumentException when UUID format is malformed")
    void shouldThrowContextualExceptionOnMalformedUuid(String malformed) {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> UserId.fromString(malformed));
        assertTrue(ex.getMessage().contains("Invalid UserId format: " + malformed));
        assertNotNull(ex.getCause());
    }

    @Test
    @DisplayName("Should generate valid non-nil UserId")
    void shouldGenerateValidUserId() {
        UserId generated1 = UserId.generate();
        UserId generated2 = UserId.generate();

        assertNotNull(generated1);
        assertNotNull(generated2);
        assertNotEquals(generated1, generated2);
        assertNotEquals(NIL_UUID, generated1.value());
    }

    @Test
    @DisplayName("Should satisfy equality contract based on UUID value")
    void shouldSatisfyEqualityContract() {
        UUID raw = UUID.randomUUID();
        UserId id1 = new UserId(raw);
        UserId id2 = new UserId(raw);

        assertEquals(id1, id2);
        assertEquals(id1.hashCode(), id2.hashCode());
    }

    @Test
    @DisplayName("Should be serializable with valid serialVersionUID")
    void shouldBeSerializable() throws Exception {
        UserId original = UserId.generate();

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(original);
        }

        UserId deserialized;
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(baos.toByteArray()))) {
            deserialized = (UserId) ois.readObject();
        }

        assertEquals(original, deserialized);
    }
}
