package com.erp.auth.domain.model;

public enum RoleCode {
    SUPERADMIN,
    WORKSHOP_ADMIN,
    SERVICE_ADVISOR,
    TECHNICIAN,
    CUSTOMER,
    // Backward-compatibility legacy aliases
    ADMIN_TALLER,
    ASESOR,
    MECANICO;

    public static RoleCode fromString(String code) {
        if (code == null) {
            throw new IllegalArgumentException("El código de rol no puede ser nulo");
        }
        return RoleCode.valueOf(code.trim().toUpperCase());
    }
}
