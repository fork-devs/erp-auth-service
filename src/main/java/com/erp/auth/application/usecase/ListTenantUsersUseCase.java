package com.erp.auth.application.usecase;

import com.erp.auth.domain.model.User;
import com.erp.auth.domain.valueobject.TenantId;

import java.util.List;

/**
 * Listado de los usuarios de un taller.
 *
 * <p>Existe como caso de uso para que el controlador REST no dependa
 * directamente de un puerto de dominio.
 */
public interface ListTenantUsersUseCase {

    List<User> listByTenant(TenantId tenantId);
}
