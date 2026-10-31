package com.erp.auth.application.usecase;

import com.erp.auth.application.dto.command.SendOtpCommand;

public interface SendOtpUseCase {
    void sendOtp(SendOtpCommand command);
}
