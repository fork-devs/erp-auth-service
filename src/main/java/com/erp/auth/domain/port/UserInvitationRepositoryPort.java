package com.erp.auth.domain.port;

import com.erp.auth.domain.model.UserInvitation;
import com.erp.auth.domain.valueobject.Email;

import java.util.Optional;
import java.util.UUID;

public interface UserInvitationRepositoryPort {
    UserInvitation save(UserInvitation invitation);
    Optional<UserInvitation> findById(UUID id);
    Optional<UserInvitation> findByTokenHash(String tokenHash);
    Optional<UserInvitation> findLatestByEmailAndTenantId(Email email, UUID tenantId);
    void invalidateAllByEmailAndTenantId(Email email, UUID tenantId);
}
