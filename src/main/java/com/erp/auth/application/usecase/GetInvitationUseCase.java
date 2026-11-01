package com.erp.auth.application.usecase;

import com.erp.auth.application.dto.result.InvitationDetailsResult;

public interface GetInvitationUseCase {
    InvitationDetailsResult getInvitation(String rawToken);
}
