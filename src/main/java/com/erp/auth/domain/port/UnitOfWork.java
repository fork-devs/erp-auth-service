package com.erp.auth.domain.port;

import java.util.function.Supplier;

/**
 * Limite transaccional de una operacion de negocio.
 *
 * <p>Es una abstraccion del dominio, sin dependencias de framework, para que
 * la capa de aplicacion pueda exigir que una operacion que escribe en varios
 * repositorios se confirme de forma conjunta sin importar como se
 * implementa la transaccion.
 *
 * <p>Sin el, cada llamada a un repositorio abre su propia transaccion: dos
 * escrituras consecutivas son dos transacciones distintas, y una operacion
 * que necesita ser atomica no lo puede ser. La rotacion del token de
 * refresco es el caso claro: si la revocacion del token anterior se confirma
 * y la creacion del nuevo falla, el usuario se queda sin ningun token
 * valido, pese a haber iniciado sesion correctamente.
 */
public interface UnitOfWork {

    void runInTransaction(Runnable work);

    <T> T callInTransaction(Supplier<T> work);
}
