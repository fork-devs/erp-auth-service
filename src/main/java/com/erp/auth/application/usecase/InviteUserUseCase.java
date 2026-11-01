package com.erp.auth.application.usecase;

import com.erp.auth.application.dto.command.InviteUserCommand;
import com.erp.auth.application.dto.result.InviteUserResult;

public interface InviteUserUseCase {
    InviteUserResult invite(InviteUserCommand command);
}
