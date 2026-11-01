package com.erp.auth.application.usecase;

import com.erp.auth.application.dto.command.ForgotPasswordCommand;
import com.erp.auth.application.dto.command.ResetPasswordCommand;

public interface PasswordResetUseCase {
    /**
     * Requests a password reset token.
     *
     * <p>The token is delivered securely to the recipient via the notification port
     * rather than returned in the API response, preventing account takeover by unauthorized requesters.
     *
     * @param command forgot password command
     */
    void requestPasswordReset(ForgotPasswordCommand command);

    void resetPassword(ResetPasswordCommand command);
}
