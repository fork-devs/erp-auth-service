package com.erp.auth.application.service;

import com.erp.auth.application.usecase.ListTenantUsersUseCase;
import com.erp.auth.domain.model.User;
import com.erp.auth.domain.port.UserRepositoryPort;
import com.erp.auth.domain.valueobject.TenantId;

import java.util.List;

public class ListTenantUsersService implements ListTenantUsersUseCase {

    private final UserRepositoryPort userRepositoryPort;

    public ListTenantUsersService(UserRepositoryPort userRepositoryPort) {
        this.userRepositoryPort = userRepositoryPort;
    }

    @Override
    public List<User> listByTenant(TenantId tenantId) {
        return userRepositoryPort.findAllByTenantId(tenantId);
    }
}
