package com.erp.auth.domain;

import com.erp.auth.domain.model.RoleCode;
import com.erp.auth.domain.model.UserInvitation;
import com.erp.auth.domain.valueobject.Email;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class UserInvitationTest {

    @Test
    @DisplayName("Should create valid active invitation")
    void shouldCreateValidActiveInvitation() {
        UUID tenantId = UUID.randomUUID();
        Email email = Email.of("mechanic@workshop.pe");
        UserInvitation invitation = UserInvitation.create(
                tenantId,
                email,
                "Carlos Ramos",
                RoleCode.TECHNICIAN,
                "hash123",
                Duration.ofHours(48)
        );

        assertThat(invitation.getId()).isNotNull();
        assertThat(invitation.getTenantId()).isEqualTo(tenantId);
        assertThat(invitation.getEmail()).isEqualTo(email);
        assertThat(invitation.getFullName()).isEqualTo("Carlos Ramos");
        assertThat(invitation.getRole()).isEqualTo(RoleCode.TECHNICIAN);
        assertThat(invitation.isValid()).isTrue();
        assertThat(invitation.isExpired()).isFalse();
        assertThat(invitation.isAccepted()).isFalse();
    }

    @Test
    @DisplayName("Should accept valid invitation once and reject second acceptance")
    void shouldAcceptValidInvitation() {
        UserInvitation invitation = UserInvitation.create(
                UUID.randomUUID(),
                Email.of("mechanic@workshop.pe"),
                "Carlos Ramos",
                RoleCode.TECHNICIAN,
                "hash123",
                Duration.ofHours(48)
        );

        invitation.accept();
        assertThat(invitation.isAccepted()).isTrue();
        assertThat(invitation.isValid()).isFalse();
        assertThat(invitation.getAcceptedAt()).isNotNull();

        assertThatThrownBy(invitation::accept)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("ya ha sido aceptada");
    }

    @Test
    @DisplayName("Should reject acceptance of expired invitation")
    void shouldRejectExpiredInvitation() {
        UserInvitation invitation = new UserInvitation(
                UUID.randomUUID(),
                UUID.randomUUID(),
                Email.of("mechanic@workshop.pe"),
                "Carlos Ramos",
                RoleCode.TECHNICIAN,
                "hash123",
                Instant.now().minus(Duration.ofMinutes(1)),
                null,
                Instant.now().minus(Duration.ofHours(1))
        );

        assertThat(invitation.isExpired()).isTrue();
        assertThat(invitation.isValid()).isFalse();

        assertThatThrownBy(invitation::accept)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("ha expirado");
    }
}
