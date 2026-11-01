package com.erp.auth.application.dto.command;

public record AcceptInvitationCommand(
        String token,
        String password
) {}
