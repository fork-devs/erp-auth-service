package com.erp.auth.application.usecase;

import com.erp.auth.application.dto.command.ForgotPasswordCommand;
import com.erp.auth.application.dto.command.ResetPasswordCommand;

public interface PasswordResetUseCase {
    /**
     * Solicita el restablecimiento de la contrasena.
     *
     * <p>No devuelve el token: se entrega al destinatario por el puerto de
     * notificacion. Devolverlo seria devolver la credencial a quien la pide,
     * con lo que cualquiera podria restablecer la contrasena de cualquier
     * cuenta.
     */
    void requestPasswordReset(ForgotPasswordCommand command);

    void resetPassword(ResetPasswordCommand command);
}
