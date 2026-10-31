package com.erp.auth.infrastructure.security;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class UserSecurityServiceTest {

    private UserSecurityService securityService;

    @BeforeEach
    void setUp() {
        securityService = new UserSecurityService();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("GIVEN matching user id WHEN isCurrentUser THEN returns true")
    void testMatchingUser() {
        UUID userId = UUID.randomUUID();
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                userId.toString(),
                "n/a",
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );
        SecurityContextHolder.getContext().setAuthentication(auth);

        assertThat(securityService.isCurrentUser(userId)).isTrue();
    }

    @Test
    @DisplayName("GIVEN non-matching user id but ADMIN role WHEN isCurrentUser THEN returns true")
    void testAdminUserAccessingDifferentId() {
        UUID principalId = UUID.randomUUID();
        UUID targetId = UUID.randomUUID();
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                principalId.toString(),
                "n/a",
                List.of(new SimpleGrantedAuthority("ROLE_WORKSHOP_ADMIN"))
        );
        SecurityContextHolder.getContext().setAuthentication(auth);

        assertThat(securityService.isCurrentUser(targetId)).isTrue();
    }

    @Test
    @DisplayName("GIVEN non-matching user id and USER role WHEN isCurrentUser THEN returns false")
    void testNonAdminAccessingDifferentId() {
        UUID principalId = UUID.randomUUID();
        UUID targetId = UUID.randomUUID();
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                principalId.toString(),
                "n/a",
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );
        SecurityContextHolder.getContext().setAuthentication(auth);

        assertThat(securityService.isCurrentUser(targetId)).isFalse();
    }

    @Test
    @DisplayName("GIVEN unauthenticated context WHEN isCurrentUser THEN returns false")
    void testUnauthenticated() {
        UUID targetId = UUID.randomUUID();
        SecurityContextHolder.clearContext();

        assertThat(securityService.isCurrentUser(targetId)).isFalse();
    }
}
