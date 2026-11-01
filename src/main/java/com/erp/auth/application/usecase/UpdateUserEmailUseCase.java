package com.erp.auth.application.usecase;

import com.erp.auth.application.dto.command.UpdateUserEmailCommand;
import com.erp.auth.application.dto.result.AuthResult;

public interface UpdateUserEmailUseCase {
    AuthResult updateEmail(UpdateUserEmailCommand command);
}
