package com.erp.auth.domain;

import com.erp.auth.domain.exception.UserAlreadyExistsException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Domain - UserAlreadyExistsException CRLF Sanitization Test")
class UserAlreadyExistsExceptionTest {

    @Test
    @DisplayName("Should replace CRLF characters with underscore to prevent log injection")
    void shouldSanitizeCrlfInEmail() {
        String taintedInput = "attacker@evil.com\r\n2026-11-07 INFO -- forged log entry";
        UserAlreadyExistsException exception = new UserAlreadyExistsException(taintedInput);

        assertThat(exception.getMessage())
                .doesNotContain("\r")
                .doesNotContain("\n")
                .contains("attacker@evil.com__2026-11-07 INFO -- forged log entry");
    }

    @Test
    @DisplayName("Should handle null email safely")
    void shouldHandleNullEmail() {
        UserAlreadyExistsException exception = new UserAlreadyExistsException(null);
        assertThat(exception.getMessage()).contains("null");
    }

    @Test
    @DisplayName("Should preserve error code and support cause")
    void shouldPreserveErrorCodeAndCause() {
        RuntimeException cause = new RuntimeException("Constraint violation");
        UserAlreadyExistsException exception = new UserAlreadyExistsException("user@example.com", cause);

        assertThat(exception.getErrorCode()).isEqualTo("AUTH_USER_ALREADY_EXISTS");
        assertThat(exception.getCause()).isSameAs(cause);
    }
}
