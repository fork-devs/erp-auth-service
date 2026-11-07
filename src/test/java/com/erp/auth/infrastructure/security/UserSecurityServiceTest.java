package com.erp.auth.infrastructure.security;

import com.erp.auth.domain.model.User;
import com.erp.auth.domain.port.UserRepositoryPort;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.domain.valueobject.PasswordHash;
import com.erp.auth.domain.valueobject.TenantId;
import com.erp.auth.infrastructure.persistence.rls.TenantContextHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("Infrastructure - UserSecurityService Multi-Tenant Hardening Test")
class UserSecurityServiceTest {

    @Mock
    private UserRepositoryPort userRepositoryPort;

    private UserSecurityService securityService;

    @BeforeEach
    void setUp() {
        securityService = new UserSecurityService(userRepositoryPort);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
        TenantContextHolder.clear();
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
    @DisplayName("GIVEN SUPERADMIN role WHEN isCurrentUser on any user THEN returns true")
    void testSuperadminAccessingAnyUser() {
        UUID principalId = UUID.randomUUID();
        UUID targetId = UUID.randomUUID();
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                principalId.toString(),
                "n/a",
                List.of(new SimpleGrantedAuthority("ROLE_SUPERADMIN"))
        );
        SecurityContextHolder.getContext().setAuthentication(auth);

        assertThat(securityService.isCurrentUser(targetId)).isTrue();
    }

    @Test
    @DisplayName("GIVEN WORKSHOP_ADMIN and user in SAME tenant WHEN isCurrentUser THEN returns true")
    void testWorkshopAdminAccessingUserInSameTenant() {
        UUID principalId = UUID.randomUUID();
        UUID targetId = UUID.randomUUID();
        UUID tenantId = UUID.randomUUID();

        TenantContextHolder.setTenantId(tenantId);

        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                principalId.toString(),
                "n/a",
                List.of(new SimpleGrantedAuthority("ROLE_WORKSHOP_ADMIN"))
        );
        SecurityContextHolder.getContext().setAuthentication(auth);

        User targetUser = User.create(
                new TenantId(tenantId),
                new Email("target@taller.pe"),
                new PasswordHash("hash"),
                "Target User",
                Set.of()
        );
        when(userRepositoryPort.findByIdAndTenantId(targetId, new TenantId(tenantId)))
                .thenReturn(Optional.of(targetUser));

        assertThat(securityService.isCurrentUser(targetId)).isTrue();
    }

    @Test
    @DisplayName("GIVEN WORKSHOP_ADMIN and user in DIFFERENT tenant (Cross-Tenant P0) WHEN isCurrentUser THEN returns false")
    void testWorkshopAdminBlockedFromAccessingUserInDifferentTenant() {
        UUID principalId = UUID.randomUUID();
        UUID targetId = UUID.randomUUID();
        UUID tenantA = UUID.randomUUID();

        TenantContextHolder.setTenantId(tenantA);

        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                principalId.toString(),
                "n/a",
                List.of(new SimpleGrantedAuthority("ROLE_WORKSHOP_ADMIN"))
        );
        SecurityContextHolder.getContext().setAuthentication(auth);

        // Target user does NOT belong to Tenant A
        when(userRepositoryPort.findByIdAndTenantId(targetId, new TenantId(tenantA)))
                .thenReturn(Optional.empty());

        assertThat(securityService.isCurrentUser(targetId)).isFalse();
    }

    @Test
    @DisplayName("GIVEN WORKSHOP_ADMIN with NO tenant context WHEN isCurrentUser THEN returns false")
    void testWorkshopAdminWithNoTenantContextReturnsFalse() {
        UUID principalId = UUID.randomUUID();
        UUID targetId = UUID.randomUUID();

        TenantContextHolder.clear();

        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                principalId.toString(),
                "n/a",
                List.of(new SimpleGrantedAuthority("ROLE_WORKSHOP_ADMIN"))
        );
        SecurityContextHolder.getContext().setAuthentication(auth);

        assertThat(securityService.isCurrentUser(targetId)).isFalse();
        verifyNoInteractions(userRepositoryPort);
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
