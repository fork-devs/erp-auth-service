package com.erp.auth.interfaces.rest.advice;

import com.erp.auth.domain.exception.AccountLockedException;
import com.erp.auth.domain.exception.DomainException;
import com.erp.auth.domain.exception.InvalidCredentialsException;
import com.erp.auth.domain.exception.InvalidTokenException;
import com.erp.auth.domain.exception.TokenExpiredException;
import com.erp.auth.domain.exception.RoleNotAssignableException;
import com.erp.auth.domain.exception.TenantContextMissingException;
import com.erp.auth.domain.exception.TokenRevokedException;
import com.erp.auth.domain.exception.UserAlreadyExistsException;
import com.erp.auth.domain.exception.UserNotFoundException;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.net.URI;
import java.time.Instant;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

@RestControllerAdvice
public class GlobalRestExceptionHandler {

    private static final org.slf4j.Logger log =
            org.slf4j.LoggerFactory.getLogger(GlobalRestExceptionHandler.class);

    private final MessageSource messageSource;

    public GlobalRestExceptionHandler() {
        this(null);
    }

    public GlobalRestExceptionHandler(MessageSource messageSource) {
        this.messageSource = messageSource;
    }

    private String getMessage(String code, String defaultMessage, Object... args) {
        if (messageSource == null) {
            return defaultMessage;
        }
        Locale locale = LocaleContextHolder.getLocale();
        return messageSource.getMessage(code, args, defaultMessage, locale);
    }

    /**
     * Account lockout returns an identical response to invalid credentials.
     *
     * <p>Returning uniform 401 ProblemDetail responses prevents account enumeration
     * by attackers probing email addresses. The specific reason is logged securely
     * in the security event log.
     */
    @ExceptionHandler(AccountLockedException.class)
    public ResponseEntity<ProblemDetail> handleAccountLocked(AccountLockedException ex) {
        // Log the exception details internally while returning a uniform response to the client
        log.warn("Cuenta bloqueada: {}", ex.getMessage(), ex);
        String detail = getMessage("error.auth.account-locked.detail", ex.getMessage());
        String title = getMessage("error.auth.account-locked.title", "Credenciales Inválidas");
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, detail);
        problem.setTitle(title);
        problem.setType(URI.create("https://errors.erp-automotriz.com/auth/invalid-credentials"));
        problem.setProperty("errorCode", ex.getErrorCode());
        problem.setProperty("timestamp", Instant.now());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(problem);
    }

    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<ProblemDetail> handleInvalidCredentials(InvalidCredentialsException ex) {
        log.info("Credenciales invalidas: {}", ex.getMessage());
        String detail = getMessage("error.auth.invalid-credentials.detail", ex.getMessage());
        String title = getMessage("error.auth.invalid-credentials.title", "Credenciales Inválidas");
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, detail);
        problem.setTitle(title);
        problem.setType(URI.create("https://errors.erp-automotriz.com/auth/invalid-credentials"));
        problem.setProperty("errorCode", ex.getErrorCode());
        problem.setProperty("timestamp", Instant.now());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(problem);
    }

    @ExceptionHandler({InvalidTokenException.class, TokenExpiredException.class, TokenRevokedException.class})
    public ResponseEntity<ProblemDetail> handleTokenExceptions(DomainException ex) {
        String detailKey = ex instanceof TokenExpiredException ? "error.auth.token-expired.detail" :
                (ex instanceof TokenRevokedException ? "error.auth.token-revoked.detail" : "error.auth.token-invalid.detail");
        String titleKey = ex instanceof TokenExpiredException ? "error.auth.token-expired.title" :
                (ex instanceof TokenRevokedException ? "error.auth.token-revoked.title" : "error.auth.token-invalid.title");
        String detail = getMessage(detailKey, ex.getMessage());
        String title = getMessage(titleKey, "Token No Válido");
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, detail);
        problem.setTitle(title);
        problem.setType(URI.create("https://errors.erp-automotriz.com/auth/token-invalid"));
        problem.setProperty("errorCode", ex.getErrorCode());
        problem.setProperty("timestamp", Instant.now());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(problem);
    }

    @ExceptionHandler(UserAlreadyExistsException.class)
    public ResponseEntity<ProblemDetail> handleUserAlreadyExists(UserAlreadyExistsException ex) {
        String detail = getMessage("error.auth.user-already-exists.detail", ex.getMessage());
        String title = getMessage("error.auth.user-already-exists.title", "Usuario Ya Existe");
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, detail);
        problem.setTitle(title);
        problem.setType(URI.create("https://errors.erp-automotriz.com/auth/user-conflict"));
        problem.setProperty("errorCode", ex.getErrorCode());
        problem.setProperty("timestamp", Instant.now());
        return ResponseEntity.status(HttpStatus.CONFLICT).body(problem);
    }

    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<ProblemDetail> handleUserNotFound(UserNotFoundException ex) {
        String detail = getMessage("error.auth.user-not-found.detail", ex.getMessage());
        String title = getMessage("error.auth.user-not-found.title", "Usuario No Encontrado");
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, detail);
        problem.setTitle(title);
        problem.setType(URI.create("https://errors.erp-automotriz.com/auth/user-not-found"));
        problem.setProperty("errorCode", ex.getErrorCode());
        problem.setProperty("timestamp", Instant.now());
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(problem);
    }

    /**
     * Maps method-level security access denials to HTTP 403 Forbidden.
     * Prevents unhandled AccessDeniedException from falling through to a generic 500 error.
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ProblemDetail> handleAccessDenied(AccessDeniedException ex) {
        String detail = getMessage("error.auth.access-denied.detail", "No tiene permisos para realizar esta operacion.");
        String title = getMessage("error.auth.access-denied.title", "Acceso Denegado");
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.FORBIDDEN, detail);
        problem.setTitle(title);
        problem.setType(URI.create("https://errors.erp-automotriz.com/auth/access-denied"));
        problem.setProperty("errorCode", "AUTH_ACCESS_DENIED");
        problem.setProperty("timestamp", Instant.now());
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(problem);
    }

    @ExceptionHandler(RoleNotAssignableException.class)
    public ResponseEntity<ProblemDetail> handleRoleNotAssignable(RoleNotAssignableException ex) {
        String detail = getMessage("error.auth.role-not-assignable.detail", ex.getMessage());
        String title = getMessage("error.auth.role-not-assignable.title", "Rol No Concedible");
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.FORBIDDEN, detail);
        problem.setTitle(title);
        problem.setType(URI.create("https://errors.erp-automotriz.com/auth/role-not-assignable"));
        problem.setProperty("errorCode", ex.getErrorCode());
        problem.setProperty("timestamp", Instant.now());
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(problem);
    }

    @ExceptionHandler(TenantContextMissingException.class)
    public ResponseEntity<ProblemDetail> handleTenantContextMissing(TenantContextMissingException ex) {
        String detail = getMessage("error.auth.tenant-context-missing.detail", ex.getMessage());
        String title = getMessage("error.auth.tenant-context-missing.title", "Contexto de Taller Ausente");
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.FORBIDDEN, detail);
        problem.setTitle(title);
        problem.setType(URI.create("https://errors.erp-automotriz.com/auth/tenant-context-missing"));
        problem.setProperty("errorCode", ex.getErrorCode());
        problem.setProperty("timestamp", Instant.now());
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(problem);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ProblemDetail> handleValidationErrors(MethodArgumentNotValidException ex) {
        String detail = getMessage("error.auth.validation-error.detail", "Error de validación en la solicitud.");
        String title = getMessage("error.auth.validation-error.title", "Solicitud Inválida");
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, detail);
        problem.setTitle(title);
        problem.setType(URI.create("https://errors.erp-automotriz.com/auth/validation-error"));

        Map<String, String> fieldErrors = new HashMap<>();
        for (FieldError error : ex.getBindingResult().getFieldErrors()) {
            fieldErrors.put(error.getField(), error.getDefaultMessage());
        }

        problem.setProperty("invalidParams", fieldErrors);
        problem.setProperty("errorCode", "VALIDATION_ERROR");
        problem.setProperty("timestamp", Instant.now());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(problem);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ProblemDetail> handleIllegalArgument(IllegalArgumentException ex) {
        String detail = getMessage("error.auth.invalid-argument.detail", ex.getMessage());
        String title = getMessage("error.auth.invalid-argument.title", "Argumento Inválido");
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, detail);
        problem.setTitle(title);
        problem.setProperty("timestamp", Instant.now());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(problem);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ProblemDetail> handleGeneralException(Exception ex) {
        // Log full exception stack trace internally for diagnostics while returning generic error
        log.error("Error no controlado: {}", ex.getMessage(), ex);

        String detail = getMessage("error.auth.internal-error.detail", "Ha ocurrido un error interno en el servidor.");
        String title = getMessage("error.auth.internal-error.title", "Error Interno");
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.INTERNAL_SERVER_ERROR, detail);
        problem.setTitle(title);
        problem.setProperty("timestamp", Instant.now());
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(problem);
    }
}
