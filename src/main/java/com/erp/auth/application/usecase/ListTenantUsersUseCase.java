package com.erp.auth.application.usecase;

import com.erp.auth.domain.model.User;
import com.erp.auth.domain.valueobject.TenantId;

import java.util.List;

/**
 * Use case to list all users belonging to a workshop tenant.
 *
 * <p>Decouples the REST interface from direct domain port access.
 */
public interface ListTenantUsersUseCase {

    List<User> listByTenant(TenantId tenantId);
}
