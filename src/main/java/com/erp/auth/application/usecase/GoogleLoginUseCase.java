package com.erp.auth.application.usecase;

import com.erp.auth.application.dto.command.GoogleLoginCommand;
import com.erp.auth.application.dto.result.AuthResult;

public interface GoogleLoginUseCase {
    AuthResult loginWithGoogle(GoogleLoginCommand command);
}
