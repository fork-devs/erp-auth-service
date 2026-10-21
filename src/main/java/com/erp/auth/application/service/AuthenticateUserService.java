package com.erp.auth.application.service;

import com.erp.auth.application.dto.command.LoginCommand;
import com.erp.auth.application.dto.result.AuthResult;
import com.erp.auth.application.usecase.AuthenticateUserUseCase;
import com.erp.auth.domain.exception.AccountLockedException;
import com.erp.auth.domain.exception.InvalidCredentialsException;
import com.erp.auth.domain.model.RefreshToken;
import com.erp.auth.domain.model.User;
import com.erp.auth.domain.port.PasswordEncoderPort;
import com.erp.auth.domain.port.RefreshTokenRepositoryPort;
import com.erp.auth.domain.exception.InvalidSecondFactorCodeException;
import com.erp.auth.domain.port.SecondFactorPort;
import com.erp.auth.domain.port.SecondFactorRepositoryPort;
import com.erp.auth.domain.port.TokenSignerPort;
import com.erp.auth.domain.port.UnitOfWork;
import com.erp.auth.domain.port.UserRepositoryPort;
import com.erp.auth.domain.valueobject.Email;
import com.erp.auth.domain.valueobject.TenantId;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.Set;
import java.util.stream.Collectors;

public class AuthenticateUserService implements AuthenticateUserUseCase {

    /**
     * Hash de un texto que no corresponde a ninguna cuenta. Se usa para
     * igualar el tiempo de respuesta cuando la cuenta no existe: verificar
     * contra el es lo que cuesta el tiempo del hash.
     */
    private static final String HASH_SENUELO =
            "$2a$12$RAmvlO5s9LG2urup52BBsuDqh0/WakqD.ufHw41ey9CHK10OyvEb2";

    private final UserRepositoryPort userRepositoryPort;
    private final RefreshTokenRepositoryPort refreshTokenRepositoryPort;
    private final PasswordEncoderPort passwordEncoderPort;
    private final TokenSignerPort tokenSignerPort;
    private final int maxFailedAttempts;
    private final Duration lockDuration;
    private final SecondFactorPort secondFactorPort;
    private final SecondFactorRepositoryPort secondFactorRepositoryPort;
    private final UnitOfWork unitOfWork;

    public AuthenticateUserService(
            UserRepositoryPort userRepositoryPort,
            RefreshTokenRepositoryPort refreshTokenRepositoryPort,
            PasswordEncoderPort passwordEncoderPort,
            TokenSignerPort tokenSignerPort,
            int maxFailedAttempts,
            Duration lockDuration,
            SecondFactorPort secondFactorPort,
            SecondFactorRepositoryPort secondFactorRepositoryPort,
            UnitOfWork unitOfWork) {
        this.userRepositoryPort = userRepositoryPort;
        this.refreshTokenRepositoryPort = refreshTokenRepositoryPort;
        this.passwordEncoderPort = passwordEncoderPort;
        this.tokenSignerPort = tokenSignerPort;
        this.maxFailedAttempts = maxFailedAttempts;
        this.lockDuration = lockDuration;
        this.secondFactorPort = secondFactorPort;
        this.secondFactorRepositoryPort = secondFactorRepositoryPort;
        this.unitOfWork = unitOfWork;
    }

    /**
     * Indica si la cuenta ha quedado bloqueada tras el ultimo intento.
     *
     * <p>Se consulta a la base de datos, y no al objeto de dominio: el
     * contador se incremento alli, en una sentencia atomica, de modo que el
     * valor que se consulta es el que queda.
     */
    private boolean cuentaBloqueada(UUID userId, TenantId tenantId) {
        return userRepositoryPort.findByIdAndTenantId(userId, tenantId)
                .map(User::isAccountLocked)
                .orElse(false);
    }

    /**
     * Verifica el codigo de segundo factor.
     *
     * <p>El codigo se acepta si corresponde al secreto enrolado Y no se ha
     * usado antes: un codigo vale durante su intervalo y el siguiente, de modo
     * que sin registrar el ultimo intervalo aceptado el mismo codigo podria
     * usarse dos veces.
     */
    private boolean segundoFactorValido(User user, String codigo) {
        if (codigo == null || codigo.isBlank()) {
            return false;
        }

        String secreto = secondFactorRepositoryPort.findSecret(user.getId()).orElse(null);
        if (secreto == null) {
            return false;
        }

        Optional<Long> contador = secondFactorPort.verify(secreto, codigo, Instant.now());
        if (contador.isEmpty()) {
            return false;
        }

        Long ultimo = secondFactorRepositoryPort.findLastAcceptedCounter(user.getId()).orElse(-1L);
        if (contador.get() <= ultimo) {
            // El codigo ya se habia usado.
            return false;
        }

        unitOfWork.runInTransaction(() ->
                secondFactorRepositoryPort.recordAcceptedCounter(user.getId(), contador.get()));
        return true;
    }

    @Override
    public AuthResult authenticate(LoginCommand command) {
        if (command.email() == null || command.password() == null) {
            throw new InvalidCredentialsException("Correo y contraseña son obligatorios");
        }

        if (command.tenantId() == null) {
            throw new InvalidCredentialsException("El identificador de taller es obligatorio para iniciar sesion");
        }

        Email email = Email.of(command.email());
        Optional<User> userOpt = userRepositoryPort.findByEmailAndTenantId(email, new TenantId(command.tenantId()));

        if (userOpt.isEmpty()) {
            // Cuando la cuenta no existe, se verifica la contrasena contra un
            // hash SENUELO. Sin esa verificacion, el tiempo de respuesta
            // delata si la cuenta existe: la busqueda de una cuenta
            // inexistente es inmediata, y la de una existente cuesta el tiempo
            // del hash. La diferencia basta para enumerar las cuentas.
            passwordEncoderPort.matches(command.password(), HASH_SENUELO);
            throw new InvalidCredentialsException();
        }

        User user = userOpt.get();

        // La contrasena se verifica SIEMPRE, antes de responder por
        // cualquier motivo. Si la cuenta esta bloqueada y se respondiera
        // sin verificar, el tiempo de respuesta delataria el estado de la
        // cuenta: un atacante que solo conozca el correo distingue
        // "esta bloqueada" de "no existe".
        boolean passwordMatches = passwordEncoderPort.matches(command.password(), user.getPasswordHash().getValue());

        // Verificar si la cuenta está bloqueada por intentos fallidos (QA-5)
        if (user.isAccountLocked()) {
            throw new AccountLockedException(user.getLockedUntil());
        }

        if (!passwordMatches) {
            // El intento fallido se confirma en SU PROPIA transaccion. No puede
            // ir dentro del limite transaccional del inicio de sesion: la
            // autenticacion fallida lanza una excepcion, y una excepcion
            // dentro de ese limite revertiria el contador, con lo que la
            // cuenta nunca se bloquearia por muchos intentos que se hagan.
            //
            // El incremento es ATOMICO en la base de datos: dos intentos
            // concurrentes no pueden partir del mismo valor, de modo que
            // ninguno se pierde. Con una lectura-modificacion-escritura, los
            // dos leian el mismo contador y escribian el mismo incremento, y
            // la cuenta se quedaba sin bloqueo tras muchos intentos.
            unitOfWork.runInTransaction(() -> userRepositoryPort.incrementFailedAttempts(
                    user.getId(), maxFailedAttempts, lockDuration));

            if (cuentaBloqueada(user.getId(), new TenantId(command.tenantId()))) {
                throw new AccountLockedException(user.getLockedUntil());
            }
            throw new InvalidCredentialsException();
        }

        // Cuando la cuenta tiene el segundo factor habilitado, no se emiten
        // credenciales sin un codigo valido. Un codigo incorrecto es un
        // intento fallido mas: cuenta para el bloqueo.
        if (user.isMfaEnabled() && !segundoFactorValido(user, command.secondFactorCode())) {
            user.recordFailedAttempt(maxFailedAttempts, lockDuration);
            unitOfWork.runInTransaction(() -> userRepositoryPort.save(user));

            if (user.isAccountLocked()) {
                throw new AccountLockedException(user.getLockedUntil());
            }
            throw new InvalidSecondFactorCodeException();
        }

        // El inicio de sesion se confirma como una sola operacion: el
        // contador de intentos y la creacion del refresh token van juntos.
        //
        // Antes, si la creacion del token fallaba tras restablecer el
        // contador, el usuario veia su cuenta como desbloqueada y sus
        // intentos como zerados, sin haber recibido ningun token: el sistema
        // afirmaba un acceso que nunca llego a darle.
        return unitOfWork.callInTransaction(() -> {
            // Login exitoso: restablecer intentos fallidos
            user.recordSuccessfulLogin();
            userRepositoryPort.save(user);

            // Generar Access Token (JWT firmado con RS256, 15 min)
            String accessToken = tokenSignerPort.generateAccessToken(user);

            // Generar Refresh Token con hash criptografico
            String rawRefreshToken = tokenSignerPort.generateRefreshToken(user);
            String refreshTokenHash = tokenSignerPort.hashToken(rawRefreshToken);
            Instant refreshTokenExpiry = Instant.now().plus(tokenSignerPort.getRefreshTokenDuration());

            RefreshToken refreshTokenEntity = RefreshToken.create(user.getId(), user.getTenantId().getValue(),
                    refreshTokenHash, refreshTokenExpiry);
            refreshTokenRepositoryPort.save(refreshTokenEntity);

            Set<String> roleCodes = user.getRoles().stream()
                    .map(r -> r.getCode().name())
                    .collect(Collectors.toSet());

            return new AuthResult(
                    accessToken,
                    tokenSignerPort.extractTokenId(accessToken),
                    rawRefreshToken,
                    "Bearer",
                    tokenSignerPort.getAccessTokenDuration().toSeconds(),
                    user.getId(),
                    user.getTenantId().getValue(),
                    user.getEmail().getValue(),
                    user.getFullName(),
                    roleCodes
            );
        });
    }
}
