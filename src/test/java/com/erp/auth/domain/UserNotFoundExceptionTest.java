package com.erp.auth.domain;

import com.erp.auth.domain.exception.UserNotFoundException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class UserNotFoundExceptionTest {

    @Test
    @DisplayName("should replace CRLF characters with underscore to prevent log injection")
    void shouldSanitizeCrlfInIdentifier() {
        String taintedInput = "admin@example.com\r\nINJECTED_LOG_ENTRY: fake session created";
        UserNotFoundException exception = new UserNotFoundException(taintedInput);

        assertThat(exception.getMessage())
                .doesNotContain("\r")
                .doesNotContain("\n")
                .contains("admin@example.com__INJECTED_LOG_ENTRY: fake session created");
    }

    @Test
    @DisplayName("should handle null identifier safely")
    void shouldHandleNullIdentifier() {
        UserNotFoundException exception = new UserNotFoundException(null);
        assertThat(exception.getMessage()).contains("null");
    }

    @Test
    @DisplayName("should preserve error code and support cause")
    void shouldPreserveErrorCodeAndCause() {
        RuntimeException cause = new RuntimeException("DB error");
        UserNotFoundException exception = new UserNotFoundException("user@example.com", cause);

        assertThat(exception.getErrorCode()).isEqualTo("AUTH_USER_NOT_FOUND");
        assertThat(exception.getCause()).isSameAs(cause);
        assertThat(exception.getMessage()).contains("user@example.com");
    }
}
