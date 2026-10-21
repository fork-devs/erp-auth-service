# Rotación de la clave de firma

El servicio de autenticación firma los tokens con una clave RSA cuyo material
**persiste**: se lee de la fuente configurada al arrancar, y no se genera en
memoria. Una clave efímera haría que cada reinicio invalidase todos los
tokens emitidos, lo que rompe el escalado horizontal: con varias réplicas,
cada una firmaría con una clave distinta y ninguna aceptaría los tokens de
las demás.

El identificador de la clave (`kid`) **se deriva del material**: es el hash del
módulo público. El mismo material produce siempre el mismo identificador, y
dos materiales distintos nunca lo comparten. No hay un `kid` que configurar, y
por tanto no puede quedar desincronizado de la clave que realmente se usa.

## Herramientas

- **Emitir el material** (una sola vez por clave):

  ```bash
  ./mvnw -q compile exec:java \
      -Dexec.mainClass=com.erp.auth.infrastructure.security.crypto.KeyMaterialGenerator
  ```

  La salida lleva las dos variables de entorno y el `kid` derivado, que es el
  que el servicio publicará.

- **Consultar el conjunto de claves publicado**:

  ```bash
  curl -s https://<auth-service>/.well-known/jwks.json | jq '.keys[] | {kid, alg, use}'
  ```

## Procedimiento

La rotación tiene una **ventana de solapamiento**: durante un tiempo se
aceptan las dos claves, y solo se firma con la nueva. Sin ella, en el
momento de desplegar la clave nueva todos los tokens emitidos con la clave
anterior dejan de aceptarse, y con ellos las sesiones abiertas.

### 1. Generar el material nuevo

```bash
./mvnw -q compile exec:java \
    -Dexec.mainClass=com.erp.auth.infrastructure.security.crypto.KeyMaterialGenerator \
    > /tmp/clave-nueva.env
```

Apunta el `kid` que imprime: es el identificador que tendra la clave nueva.

### 2. Cargar la clave nueva **como anterior** y reiniciar

Las propiedades de la clave anterior son:

| Propiedad | Variable de entorno |
|:---|:---|
| `erp.security.jwt.previous-private-key-pem` | `JWT_PREVIOUS_PRIVATE_KEY_PEM` |
| `erp.security.jwt.previous-public-key-pem` | `JWT_PREVIOUS_PUBLIC_KEY_PEM` |

Carga el material nuevo en esas dos variables y reinicia el servicio. En este
momento:

- el servicio **firma** con la clave vigente, que sigue siendo la antigua;
- el servicio **publica** las dos: la vigente y la anterior.

Es el estado de solapamiento. Los verificadores (gateway y hub) siguen
aceptando los tokens firmados con cualquiera de las dos, porque el conjunto
publicado contiene las dos.

### 3. Esperar a que expire la ventana de los tokens antiguos

El tiempo de vida del token de acceso es
`erp.security.jwt.access-token-expiration-minutes` (15 minutos por defecto).
Hay que esperar ese plazo **después** del despliegue del paso 2: es el tiempo
que puede tardar un token emitido con la clave antigua en dejar de presentarse.

### 4. Promover la clave nueva a vigente

Ahora sí: mueve el material nuevo a las propiedades de la clave vigente
(`erp.security.jwt.private-key-pem` y `erp.security.jwt.public-key-pem`) y
**retira** el material anterior de las propiedades de la clave anterior.

Reinicia el servicio. A partir de este momento:

- se firma únicamente con la clave nueva;
- se publica únicamente la clave nueva.

### 5. Comprobar

```bash
curl -s https://<auth-service>/.well-known/jwks.json | jq '.keys | length'   # debe ser 1
```

Y verifica que un token emitido antes de la rotación sigue siendo aceptado
durante la ventana, y que deja de aceptarse al terminar el plazo del paso 3.

## Notas

- La rotación es **manual**. Automatizarla exigiría decidir dónde reside la
  clave anterior y cómo se audita, y no es necesario para corregir el
  defecto.
- El material anterior se puede retirar en cualquier momento una vez
  superada la ventana: dejarlo puesto solo mantiene la capacidad de
  verificar tokens antiguos.
- El servicio **falla al arrancar** si el material no está disponible. Es
  intencionado: arrancar sin clave significaría emitir tokens que nadie
  podría validar después.
