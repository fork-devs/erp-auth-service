package com.erp.auth.application.usecase;

import com.erp.auth.application.dto.command.VerifyOtpCommand;

public interface VerifyOtpUseCase {
    void verifyOtp(VerifyOtpCommand command);
}
