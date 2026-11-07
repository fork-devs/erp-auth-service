package com.erp.auth.domain.exception;

public abstract class DomainException extends RuntimeException {
    private static final long serialVersionUID = 1L;
    private final String errorCode;

    protected DomainException(String errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    protected DomainException(String errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    public String getErrorCode() {
        return errorCode;
    }

    public static String sanitize(String input) {
        if (input == null) {
            return "null";
        }
        return input.replace('\r', '_').replace('\n', '_');
    }
}
