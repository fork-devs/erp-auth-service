package com.erp.auth.application.usecase;

import com.erp.auth.application.dto.command.LoginCommand;
import com.erp.auth.application.dto.result.AuthResult;

public interface AuthenticateUserUseCase {
    AuthResult authenticate(LoginCommand command);
}
