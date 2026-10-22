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
import java.util.Map;

@RestControllerAdvice
public class GlobalRestExceptionHandler {

    @ExceptionHandler(AccountLockedException.class)
    public ResponseEntity<ProblemDetail> handleAccountLocked(AccountLockedException ex) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.LOCKED, ex.getMessage());
        problem.setTitle("Cuenta Bloqueada");
        problem.setType(URI.create("https://errors.erp-automotriz.com/auth/account-locked"));
        problem.setProperty("errorCode", ex.getErrorCode());
        problem.setProperty("lockedUntil", ex.getLockedUntil());
        problem.setProperty("timestamp", Instant.now());
        return ResponseEntity.status(HttpStatus.LOCKED).body(problem);
    }

    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<ProblemDetail> handleInvalidCredentials(InvalidCredentialsException ex) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, ex.getMessage());
        problem.setTitle("Credenciales Inválidas");
        problem.setType(URI.create("https://errors.erp-automotriz.com/auth/invalid-credentials"));
        problem.setProperty("errorCode", ex.getErrorCode());
        problem.setProperty("timestamp", Instant.now());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(problem);
    }

    @ExceptionHandler({InvalidTokenException.class, TokenExpiredException.class, TokenRevokedException.class})
    public ResponseEntity<ProblemDetail> handleTokenExceptions(DomainException ex) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, ex.getMessage());
        problem.setTitle("Token No Válido");
        problem.setType(URI.create("https://errors.erp-automotriz.com/auth/token-invalid"));
        problem.setProperty("errorCode", ex.getErrorCode());
        problem.setProperty("timestamp", Instant.now());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(problem);
    }

    @ExceptionHandler(UserAlreadyExistsException.class)
    public ResponseEntity<ProblemDetail> handleUserAlreadyExists(UserAlreadyExistsException ex) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, ex.getMessage());
        problem.setTitle("Usuario Ya Existe");
        problem.setType(URI.create("https://errors.erp-automotriz.com/auth/user-conflict"));
        problem.setProperty("errorCode", ex.getErrorCode());
        problem.setProperty("timestamp", Instant.now());
        return ResponseEntity.status(HttpStatus.CONFLICT).body(problem);
    }

    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<ProblemDetail> handleUserNotFound(UserNotFoundException ex) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, ex.getMessage());
        problem.setTitle("Usuario No Encontrado");
        problem.setType(URI.create("https://errors.erp-automotriz.com/auth/user-not-found"));
        problem.setProperty("errorCode", ex.getErrorCode());
        problem.setProperty("timestamp", Instant.now());
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(problem);
    }

    /**
     * La denegacion de la seguridad a nivel de metodo se resuelve aqui y no en
     * el filtro de seguridad: el resolutor de excepciones del dispatcher la
     * intercepta antes de que llegue al filtro, de modo que sin este
     * mapeo un acceso denegado se responderia con un 500 en lugar de un 403.
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ProblemDetail> handleAccessDenied(AccessDeniedException ex) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.FORBIDDEN,
                "No tiene permisos para realizar esta operacion.");
        problem.setTitle("Acceso Denegado");
        problem.setType(URI.create("https://errors.erp-automotriz.com/auth/access-denied"));
        problem.setProperty("errorCode", "AUTH_ACCESS_DENIED");
        problem.setProperty("timestamp", Instant.now());
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(problem);
    }

    @ExceptionHandler(RoleNotAssignableException.class)
    public ResponseEntity<ProblemDetail> handleRoleNotAssignable(RoleNotAssignableException ex) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.FORBIDDEN, ex.getMessage());
        problem.setTitle("Rol No Concedible");
        problem.setType(URI.create("https://errors.erp-automotriz.com/auth/role-not-assignable"));
        problem.setProperty("errorCode", ex.getErrorCode());
        problem.setProperty("timestamp", Instant.now());
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(problem);
    }

    @ExceptionHandler(TenantContextMissingException.class)
    public ResponseEntity<ProblemDetail> handleTenantContextMissing(TenantContextMissingException ex) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.FORBIDDEN, ex.getMessage());
        problem.setTitle("Contexto de Taller Ausente");
        problem.setType(URI.create("https://errors.erp-automotriz.com/auth/tenant-context-missing"));
        problem.setProperty("errorCode", ex.getErrorCode());
        problem.setProperty("timestamp", Instant.now());
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(problem);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ProblemDetail> handleValidationErrors(MethodArgumentNotValidException ex) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, "Error de validación en la solicitud.");
        problem.setTitle("Solicitud Inválida");
        problem.setType(URI.create("https://errors.erp-automotriz.com/auth/validation-error"));

        Map<String, String> fieldErrors = new HashMap<>();
        for (FieldError error : ex.getBindingResult().getFieldErrors()) {
            fieldErrors.put(error.getField(), error.getDefaultMessage());
        }

        problem.setProperty("invalidParams", fieldErrors);
        problem.setProperty("timestamp", Instant.now());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(problem);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ProblemDetail> handleIllegalArgument(IllegalArgumentException ex) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, ex.getMessage());
        problem.setTitle("Argumento Inválido");
        problem.setProperty("timestamp", Instant.now());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(problem);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ProblemDetail> handleGeneralException(Exception ex) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.INTERNAL_SERVER_ERROR, "Ha ocurrido un error interno en el servidor.");
        problem.setTitle("Error Interno");
        problem.setProperty("timestamp", Instant.now());
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(problem);
    }
}
