package com.erp.auth.application.usecase;

import com.erp.auth.application.dto.result.UserResult;

import java.util.UUID;

public interface GetUserByIdUseCase {
    UserResult getUserById(UUID userId);
}
