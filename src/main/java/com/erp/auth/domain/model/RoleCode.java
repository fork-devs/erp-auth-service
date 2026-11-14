package com.erp.auth.domain.model;

import com.fasterxml.jackson.annotation.JsonCreator;

public enum RoleCode {
    SUPERADMIN,
    WORKSHOP_ADMIN,
    SERVICE_ADVISOR,
    TECHNICIAN,
    CUSTOMER;

    @JsonCreator
    public static RoleCode fromString(String code) {
        if (code == null || code.trim().isEmpty()) {
            throw new IllegalArgumentException("Role code cannot be null or blank");
        }
        String normalized = code.trim().toUpperCase();
        return switch (normalized) {
            case "SUPERADMIN", "ROLE_SUPERADMIN", "ADMIN", "ROLE_ADMIN" -> SUPERADMIN;
            case "WORKSHOP_ADMIN", "ROLE_WORKSHOP_ADMIN", "ADMIN_TALLER", "ROLE_ADMIN_TALLER", "OWNER", "ROLE_OWNER" -> WORKSHOP_ADMIN;
            case "SERVICE_ADVISOR", "ROLE_SERVICE_ADVISOR", "ASESOR", "ROLE_ASESOR" -> SERVICE_ADVISOR;
            case "TECHNICIAN", "ROLE_TECHNICIAN", "MECANICO", "ROLE_MECANICO" -> TECHNICIAN;
            case "CUSTOMER", "ROLE_CUSTOMER", "CLIENTE", "USER", "ROLE_USER" -> CUSTOMER;
            default -> {
                try {
                    yield RoleCode.valueOf(normalized);
                } catch (IllegalArgumentException e) {
                    throw new IllegalArgumentException("Invalid role code: " + code);
                }
            }
        };
    }
}
