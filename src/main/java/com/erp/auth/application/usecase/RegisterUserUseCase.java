package com.erp.auth.application.usecase;

import com.erp.auth.application.dto.command.RegisterUserCommand;
import com.erp.auth.application.dto.result.UserResult;

public interface RegisterUserUseCase {
    UserResult register(RegisterUserCommand command);
}
