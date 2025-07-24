
Guía para implementar Cuenta Única con Inji

- Crear el cliente de Oauth2
  - Configurar el redirect URI a http://<dominio principal>/redirect
  - Access token type tiene que ser JWT
  - Authentication method tiene que ser JWT Authentication
  - Autentication Signing Algorithm RS256
  
- Crear un JSON Web Key Set Document
  - debe crear un archivo jwk.json y subirlo a una URL pública, este jwk.json debe tener el siguiente formato:
  ```
  {
    "keys": [
      {
        "kty": "RSA",
        "n": "vGlYp-KV4pPCB4C1PQr4FIR5v_Uv-q34DkM1mmF-jgMSOlANNahoNX0JoVDrRrzPSQv6ZRXljUdaj6OmqH1tCEo0krnmY2HR1URVRf-oH0FVin7a7SNtWRF1Kz5qlZ8i2AewChfySfPqwIgnXbT88f01-05AXCJCGNDY7YVk4Bx8sDwqYojKp8Mmk3ueIytFVb97no60hqzp1wigqxZRjoeg_cfSIOIttTEFgJsb2Yz-ueXVJFqphOi0coF1o99mBXaJEeEH3gN1c9WNwz8TER9SoyyzDq41TnQ9r5ldz2n0QlHA2a-VExDdbcE_Iso0JhwsyLlYPspqgMyBKyi0YQ",
        "e": "AQAB",
        "alg": "RS256",
        "kid": "aaf180ad-4bcc-4eb2-8133-803c2d85a08f",
        "use": "sig"
      }
    ]
  }

  ```
  - También debe crear un archivo oidckeystore.p12, ese archivo se pondrá en la carpeta docker-compose\docker-compose-injistack\certs\ en el inji-certify y en docker-compose\certs\oidckeystore.p12 en el proyecto de Mimoto
  - el nombre del archivo y la contraseña deben ponerse en el archivo mimoto-default-properties en el proyecto de Mimoto de la siguiente manera:
  ```
  mosip.partner.crypto.p12.filename=oidckeystore.p12
  mosip.partner.crypto.p12.password=password123
  ```
  - Añadir el URI del jwk.json al cliente de Oauth2 en Ory, se peude hacer desde la consola
- El mismo scope que usará Inji para las credenciales, agregarla a Ory. El scope en Inji se peude encontrar en el proyecto de Inji Certify en `mosip.certify.key-values`, por ejemplo se puede ver aquí que el scope es `driver_license_vc_ldp`:
 mosip.certify.key-values={\
  'latest' : {\
              'credential_issuer': '${mosip.certify.identifier}',   \
              'authorization_servers': {'${mosip.certify.authorization.url}'}, \
              'credential_endpoint': '${mosipbox.public.url}${server.servlet.path}/issuance/credential', \
              'display': {{'name': 'INTRANT', 'locale': 'en'}},\
              'credential_configurations_supported' : { \
                 'DriverLicense' : {\
                    'format': 'ldp_vc',\
                    'scope' : 'driver_license_vc_ldp',\

Ese mismo scope debe agregarse en la configuración del cliente

- Ejecutar el siguiente comando:
```
ory patch oauth2-config {project.id} \
  --replace '/strategies/jwt/scope_claim="both"'
```

- El access token debe tener un c_nonce y un c_nonce_expires_in que se debe crear desde un web hook
 - Crea un servicio que genere esos valores y ponlos en una URL pública ejemplo de lo que debe devolver despues de un post request:
  ```
  {
    "session": {
        "access_token": {
            "c_nonce": "ZP2WJAIbGDtnOXFcOTny6Ajzskb0s2xawLaKU-r-hyg",
            "c_nonce_expires_in": 300
        }
    }
  }
  ```
 - Modifica el archivo de configuración de Ory para que haga lo siguiente
  - Agregue el URL del webhook que genera el c_nonce
  - Modifica el valor de `allowed_top_level_claims` para que incluya `c_nonce` y `c_nonce_expires_in`.

Modificaciones en los archivos de configuración
- En el mimoto-issuers-config.json modificar estos campos:
  ```
  "authorization_audience": "https://cuenta.digital.gob.do/oauth2/token",
  "proxy_token_endpoint": "https://cuenta.digital.gob.do/oauth2/token",
  ```
- En certify-default.properties modificar los siguientes campos
  ```
  mosip.certify.authorization.url=https://cuenta.digital.gob.do

  ...

  mosip.certify.authn.issuer-uri=https://cuenta.digital.gob.do
  mosip.certify.authn.jwk-set-uri=https://cuenta.digital.gob.do/.well-known/jwks.json
  ```

Modificación del código fuente de mimoto
Alguas configuraciones al código fuete de Mimoto son necesarias:
- En src\main\java\io\mosip\mimoto\service\impl\CredentialServiceImpl.java en el método getTokenResponse cuando se llama el método constructGetTokenRequest cambiar el último parámetro de la siguiente manera:
```
HttpEntity<MultiValueMap<String, String>> request = idpService.constructGetTokenRequest(params, issuerDTO, "https://{project.slug}.projects.oryapis.com/oauth2/token");
```
- Agregar el campo jti a los JWT, En el archivo JoseUtil.java e el método getJWT añadir el campo jti en el return
  ```
  return JWT.create()
                .withHeader(header)
                .withIssuer(clientId)
                .withSubject(clientId)
                .withAudience(audience)
                .withExpiresAt(expiresAt)
                .withIssuedAt(issuedAt)
                .withClaim("jti", UUID.randomUUID().toString())  // <--- Nuevo cambio
                .sign(Algorithm.RSA256(null, privateKey));
  ```
- También agregarlo en el método generateJwt del mismo archivo:
 ```
 Map<String, Object> payload = new HashMap<>();
        payload.put("sub", clientId);
        payload.put("aud", audience);
        payload.put("nonce", cNonce);
        payload.put("iss", clientId);
        payload.put("exp", expiresAt.toInstant().getEpochSecond());
        payload.put("iat", issuedAt.toInstant().getEpochSecond());
        payload.put("jti", UUID.randomUUID().toString());  // <--- nuevo cambio
 ```

 - Compilar el proyecto de Mimoto y hacer los cambios en el docker compose para que en vez de utilizar una imagen de dockerhub utilice una imagen creadad a partir de la compilación del código fuente
    Método con el que se compila el proyecto: `mvn clean install -Dgpg.skip=true -Dmaven.javadoc.skip=true -DskipTests=true`

Y listo con eso ya debería funcionar
# Documentación de Integración entre Cuenta Única e Inji

Esta guía te ayudará a integrar exitosamente **Cuenta Única** (basada en Ory Hydra) con **Inji**, cubriendo los aspectos esenciales para asegurar compatibilidad con flujos de credenciales verificables. Abarca configuraciones del cliente OAuth2, ajustes en el código fuente de Mimoto y servicios externos requeridos como el `c_nonce`.



## 1. Configuración del Cliente OAuth2 en Cuenta Única

Para que **Inji** pueda funcionar correctamente como un verificador dentro de un flujo OpenID Connect, es necesario configurar de forma precisa al cliente en **Cuenta Única**.

### Cambiar el Tipo de Access Token a JWT

**Cuenta Única** debe emitir access tokens en formato JWT para permitir la validación sin contacto adicional con el servidor.

Ejecuta el siguiente comando para activar la estrategia JWT:

```bash
ory patch oauth2-config \
  --project <project_id> \
  --workspace <workspace_id> \
  --replace "/oauth2/access_token_strategy=jwt"
```

### Crear y Publicar el JSON Web Key Set (JWKS)

#### Paso 1: Generar las claves RSA

```bash
openssl genpkey -algorithm RSA -out private.key -pkeyopt rsa_keygen_bits:2048
openssl rsa -in private.key -pubout -out public.key
```

#### Paso 2: Convertir a formato JWKS

Puedes usar:

* [https://mkjwk.org](https://mkjwk.org)
* Librerías como `node-jose`, `python-jose`, o `jose` en JavaScript

El JWKS debe contener la clave pública, con los campos `use: "sig"` y `alg: "RS256"`. Ejemplo:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "1",
      "alg": "RS256",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

#### Paso 3: Publicar el JWKS en una URL accesible públicamente

Puedes subirlo a:

* Un bucket de S3 con política pública
* GitHub Pages
* Cualquier CDN o hosting estático

Por ejemplo: `https://miapp.com/jwks.json`

### Paso 4: Registrar el cliente en Cuenta Única

```json
{
  "client_id": "cliente-inji",
  "token_endpoint_auth_method": "private_key_jwt",
  "jwks_uri": "https://miapp.com/jwks.json",
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "redirect_uris": ["https://inji.miapp.com/callback"],
  "scope": "openid vc_authn"
}
```



## 2. Cambios en el Código Fuente de Mimoto

Para cumplir con las expectativas del flujo de verificación de credenciales, Mimoto necesita ser modificado.

### A. Incluir el `jti` en los Tokens

El campo `jti` (JWT ID) ayuda a prevenir ataques de repetición. Puedes generarlo con `uuid`:

```javascript
const { v4: uuid } = require('uuid');
idTokenPayload.jti = uuid();
```

Colócalo antes de firmar el ID Token.

### B. Hardcodear el `aud` (Audience)

El campo `aud` debe coincidir con el identificador del verificador. Si estás trabajando sólo con Inji, puedes establecerlo así:

```javascript
idTokenPayload.aud = "https://certify.inji.org";
```

Opcionalmente, puedes hacerlo condicional si hay múltiples clientes OAuth2.



## 3. Configurar que el scope sea enviado como "scope" en vez de "scp"

Por defecto, **Cuenta Única** (basada en Ory Hydra) puede emitir el claim `scp` para representar los permisos del token. Sin embargo, Inji espera recibir `scope`.

Ejecuta lo siguiente:

```bash
ory patch oauth2-config \
  --project <project_id> \
  --workspace <workspace_id> \
  --replace "/oauth2/allowed_top_level_claims=[\"scope\",\"c_nonce\",\"c_nonce_expires_in\"]"
```

Esto asegura que el claim `scope` se incluya explícitamente en el access token.



## 4. Crear un Servicio para el `c_nonce`

Inji requiere un `c_nonce` único por flujo de autenticación. Este valor debe ser generado por un webhook que **Cuenta Única** invoca.

### A. Crear el Servicio de `c_nonce`

```javascript
const express = require('express');
const app = express();
const { v4: uuid } = require('uuid');

app.get('/c_nonce', (req, res) => {
  res.json({
    c_nonce: uuid(),
    c_nonce_expires_in: 300 // 5 minutos
  });
});

app.listen(3000, () => console.log('Servicio c_nonce corriendo en puerto 3000'));
```

### B. Publicar la URL del webhook

Debe estar disponible vía HTTPS y accesible para **Cuenta Única**. Ejemplo: `https://miapp.com/c_nonce`

### C. Configurar el webhook en Cuenta Única

```bash
ory patch oauth2-config \
  --project <project_id> \
  --workspace <workspace_id> \
  --replace "/oauth2/strategies/access_token/c_nonce_hook_url=https://miapp.com/c_nonce"
```



## Conclusión

Con esta documentación, puedes replicar una integración robusta entre **Cuenta Única** e **Inji**, asegurando compatibilidad con el modelo de credenciales verificables. Asegúrate de validar que:

* Los JWT emitidos contienen `jti`, `aud` y `scope` de manera adecuada.
* El `c_nonce` es generado dinámicamente y firmado por un endpoint confiable.
* Las llaves estén almacenadas y protegidas según buenas prácticas.

Esta integración sienta las bases para un ecosistema interoperable de identidad digital basado en estándares abiertos.
