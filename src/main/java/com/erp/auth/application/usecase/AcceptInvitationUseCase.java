package com.erp.auth.application.usecase;

import com.erp.auth.application.dto.command.AcceptInvitationCommand;
import com.erp.auth.application.dto.result.AuthResult;

public interface AcceptInvitationUseCase {
    AuthResult accept(AcceptInvitationCommand command);
}
