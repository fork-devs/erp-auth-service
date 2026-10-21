package com.erp.auth.domain.port;

/**
 * Segundo factor de autenticacion: codigos de un solo uso temporizados.
 *
 * <p>Es un puerto del dominio: no depende de ninguna biblioteca concreta de
 * verificacion, ni de framework. La implementacion de infraestructura es la
 * que sabe como se comprueba un codigo.
 *
 * <p>Las operaciones de enrolar un secreto y de verificar un codigo son las
 * unicas que el dominio necesita: el resto (persistir el secreto, registrar
 * el ultimo codigo aceptado) es de la infraestructura.
 */
public interface SecondFactorPort {

    /**
     * Genera un secreto nuevo y su enlace de enrolamiento.
     *
     * @return el secreto en Base32, que es lo que se muestra al usuario
     */
    SecondFactorSecret enroll();

    /**
     * Verifica un codigo contra un secreto.
     *
     * @param secret  el secreto enrolado por el usuario
     * @param code    el codigo que introduce el usuario
     * @param at      el instante en el que se verifica, para que la
     *                comprobacion sea determinista y verificable
     */
    boolean verify(String secret, String code, java.time.Instant at);

    /**
     * Secreto de segundo factor y su enlace de enrolamiento.
     *
     * @param secret el secreto en Base32
     * @param uri    el enlace otpauth:// con el que la aplicacion
     *               autenticadora se enrola
     */
    record SecondFactorSecret(String secret, String uri) {
    }
}
