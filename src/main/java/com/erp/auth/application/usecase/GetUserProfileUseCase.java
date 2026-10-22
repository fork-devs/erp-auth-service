package com.erp.auth.application.usecase;

import com.erp.auth.application.dto.result.UserResult;
import com.erp.auth.domain.valueobject.TenantId;

import java.util.UUID;

public interface GetUserProfileUseCase {
    UserResult getProfile(UUID userId, TenantId tenantId);
}
