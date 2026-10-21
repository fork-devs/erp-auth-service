package com.erp.auth.application.dto.command;

import com.erp.auth.domain.model.RoleCode;
import com.erp.auth.domain.valueobject.TenantId;

import java.util.Set;

/**
 * Alta de un usuario dentro de un taller.
 *
 * <p>El taller NO lo declara el cliente: lo fija el principal autenticado y
 * viaja con el comando ya resuelto. El rol que se quiere conceder tampoco se
 * acepta sin mas: el servicio lo contrasta con la matriz de roles que el
 * actor tiene permitidos.
 */
public record RegisterUserCommand(
        TenantId tenantId,
        String email,
        String password,
        String fullName,
        Set<RoleCode> requestedRoles,
        RoleCode actorRole
) {
}
