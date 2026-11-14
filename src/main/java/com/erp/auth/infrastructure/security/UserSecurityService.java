package com.erp.auth.infrastructure.security;

import com.erp.auth.domain.port.UserRepositoryPort;
import com.erp.auth.domain.valueobject.TenantId;
import com.erp.auth.infrastructure.persistence.rls.TenantContextHolder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.UUID;

@Service("userSecurityService")
public class UserSecurityService {

    private static final Set<String> WORKSHOP_ADMIN_ROLES = Set.of(
            "ROLE_WORKSHOP_ADMIN",
            "ROLE_ADMIN_TALLER",
            "ROLE_ADMIN"
    );

    private static final String SUPERADMIN_ROLE = "ROLE_SUPERADMIN";

    private final UserRepositoryPort userRepositoryPort;

    public UserSecurityService(UserRepositoryPort userRepositoryPort) {
        this.userRepositoryPort = userRepositoryPort;
    }

    public boolean isCurrentUser(UUID userId) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated() || userId == null) {
            return false;
        }

        String principalName = authentication.getName();
        if (userId.toString().equalsIgnoreCase(principalName)) {
            return true;
        }

        boolean isSuperAdmin = authentication.getAuthorities().stream()
                .anyMatch(a -> SUPERADMIN_ROLE.equals(a.getAuthority()));
        if (isSuperAdmin) {
            return true;
        }

        boolean isWorkshopAdmin = authentication.getAuthorities().stream()
                .anyMatch(a -> WORKSHOP_ADMIN_ROLES.contains(a.getAuthority()));

        if (isWorkshopAdmin) {
            UUID currentTenantId = TenantContextHolder.getTenantId();
            if (currentTenantId == null) {
                return false;
            }
            return userRepositoryPort.findByIdAndTenantId(userId, new TenantId(currentTenantId)).isPresent();
        }

        return false;
    }
}
