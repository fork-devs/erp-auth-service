package com.erp.auth.application.usecase;

import com.erp.auth.application.dto.command.RefreshTokenCommand;
import com.erp.auth.application.dto.result.AuthResult;

public interface RefreshTokenUseCase {
    AuthResult refreshToken(RefreshTokenCommand command);
}
