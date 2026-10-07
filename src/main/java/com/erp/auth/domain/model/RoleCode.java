package com.erp.auth.domain.model;

public enum RoleCode {
    SUPERADMIN,
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
