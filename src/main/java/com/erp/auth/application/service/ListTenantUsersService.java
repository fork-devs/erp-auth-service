package com.erp.auth.application.service;

import com.erp.auth.application.usecase.ListTenantUsersUseCase;
import com.erp.auth.domain.model.User;
import com.erp.auth.domain.port.UserRepositoryPort;
import com.erp.auth.domain.valueobject.TenantId;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

public class ListTenantUsersService implements ListTenantUsersUseCase {

    private final UserRepositoryPort userRepositoryPort;

    public ListTenantUsersService(UserRepositoryPort userRepositoryPort) {
        this.userRepositoryPort = userRepositoryPort;
    }

    @Override
    @Transactional(readOnly = true)
    public List<User> listByTenant(TenantId tenantId) {
        return userRepositoryPort.findAllByTenantId(tenantId);
    }
}
