package com.erp.auth.interfaces.rest.dto.response;

public record MessageResponse(
        String message,
        boolean success
) {
    public static MessageResponse of(String message) {
        return new MessageResponse(message, true);
    }
}
