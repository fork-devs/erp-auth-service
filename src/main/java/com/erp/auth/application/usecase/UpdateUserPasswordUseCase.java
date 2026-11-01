package com.erp.auth.application.usecase;

import com.erp.auth.application.dto.command.UpdateUserPasswordCommand;

public interface UpdateUserPasswordUseCase {
    void updatePassword(UpdateUserPasswordCommand command);
}
