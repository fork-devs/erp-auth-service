package com.erp.auth.infrastructure.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.UUID;

@Service("userSecurityService")
public class UserSecurityService {

    private static final Set<String> ADMIN_ROLES = Set.of(
            "ROLE_SUPERADMIN",
            "ROLE_WORKSHOP_ADMIN",
            "ROLE_ADMIN_TALLER",
            "ROLE_ADMIN"
    );

    public boolean isCurrentUser(UUID userId) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated() || userId == null) {
            return false;
        }

        String principalName = authentication.getName();
        if (userId.toString().equalsIgnoreCase(principalName)) {
            return true;
        }

        return authentication.getAuthorities().stream()
                .anyMatch(a -> ADMIN_ROLES.contains(a.getAuthority()));
    }
}
