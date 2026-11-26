package com.erp.auth.domain.model;

import com.fasterxml.jackson.annotation.JsonCreator;

public enum RoleCode {
    SUPERADMIN,
    WORKSHOP_ADMIN,
    BRANCH_MANAGER,
    SERVICE_ADVISOR,
    SECRETARY,
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
            case "WORKSHOP_ADMIN", "ROLE_WORKSHOP_ADMIN", "OWNER", "ROLE_OWNER" -> WORKSHOP_ADMIN;
            case "BRANCH_MANAGER", "ROLE_BRANCH_MANAGER" -> BRANCH_MANAGER;
            case "SERVICE_ADVISOR", "ROLE_SERVICE_ADVISOR" -> SERVICE_ADVISOR;
            case "SECRETARY", "ROLE_SECRETARY", "RECEPTIONIST", "ROLE_RECEPTIONIST" -> SECRETARY;
            case "TECHNICIAN", "ROLE_TECHNICIAN" -> TECHNICIAN;
            case "CUSTOMER", "ROLE_CUSTOMER", "USER", "ROLE_USER" -> CUSTOMER;
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
