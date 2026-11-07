package com.erp.auth.domain;

import com.erp.auth.domain.model.TokenHash;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Domain - TokenHash Value Object Test")
class TokenHashTest {

    private static final String VALID_SHA256_HEX = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    @Test
    @DisplayName("Should create TokenHash successfully with valid hex string")
    void shouldCreateTokenHashWithValidHex() {
        TokenHash hash = TokenHash.of(VALID_SHA256_HEX);

        assertNotNull(hash);
        assertEquals(VALID_SHA256_HEX, hash.getValue());
        assertEquals(VALID_SHA256_HEX, hash.toString());
    }

    @Test
    @DisplayName("Should normalize uppercase hex string to lowercase")
    void shouldNormalizeUppercaseHexToLowercase() {
        String upperHex = VALID_SHA256_HEX.toUpperCase();
        TokenHash hash = TokenHash.of(upperHex);

        assertEquals(VALID_SHA256_HEX, hash.getValue());
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t", "\n"})
    @DisplayName("Should throw IllegalArgumentException when token hash is null or blank")
    void shouldThrowWhenNullOrBlank(String invalid) {
        assertThrows(IllegalArgumentException.class, () -> TokenHash.of(invalid));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "not-a-hex-string",
            "12345", // too short (<32 chars)
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", // invalid hex characters
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85g" // 'g' is not hex
    })
    @DisplayName("Should throw IllegalArgumentException when format is not valid hex")
    void shouldThrowWhenFormatIsNotHex(String invalidHex) {
        assertThrows(IllegalArgumentException.class, () -> TokenHash.of(invalidHex));
    }

    @Test
    @DisplayName("Two TokenHash instances with same value should be equal and have same hashCode")
    void shouldBeEqualForSameValue() {
        TokenHash hash1 = TokenHash.of(VALID_SHA256_HEX);
        TokenHash hash2 = TokenHash.of(VALID_SHA256_HEX.toUpperCase());

        assertEquals(hash1, hash2);
        assertEquals(hash1.hashCode(), hash2.hashCode());
    }
}
