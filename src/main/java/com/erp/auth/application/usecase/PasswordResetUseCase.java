package com.erp.auth.application.usecase;

import com.erp.auth.application.dto.command.ForgotPasswordCommand;
import com.erp.auth.application.dto.command.ResetPasswordCommand;

public interface PasswordResetUseCase {
    String requestPasswordReset(ForgotPasswordCommand command);
    void resetPassword(ResetPasswordCommand command);
}
