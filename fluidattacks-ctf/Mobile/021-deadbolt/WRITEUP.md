# Write-up — Deadbolt (FluidVault)

| | |
|---|---|
| **CTF** | FluidAttacks CTF 2026 |
| **Categoría** | Mobile |
| **Dificultad** | Hard |
| **Puntos** | 365 |
| **Flag** | `flag{a9f852a845bf784f}` |
| **Vulnerabilidad** | KDF débil: la clave AES del vault se deriva de valores hardcodeados/adivinables, no de la biometría |

---

## 1. Enunciado

> FluidVault is a mobile password manager. Biometrics, AES-256-GCM, the works.
> Tienes: fuentes Java decompiladas del APK, `vault_backup.enc`, `vault_decrypt.py`.
> **No device or emulator required.**

Objetivo: descifrar el backup y llegar a la flag. La pista "no device required" indica
que la clave se puede reconstruir sin hardware.

---

## 2. Análisis del KDF (`CryptoManager.java`)

Pese al marketing ("biometrics, AES-256-GCM"), la clave del vault **no depende de la
biometría** ni del Android Keystore. Se deriva así:

```java
private static final String SEED = "fluidvault_master_seed_2026";
private static final byte[] SALT = hexToBytes("a915c3e00dbb5a55ba13d7cdaf3a126e");
private static final int ITERATIONS = 10000, KEY_LENGTH = 256;
private static final String DEFAULT_DEVICE_ID = "DEFAULT_DEVICE_ID";

String passphrase = SEED + getDeviceIdentifier();
// PBKDF2WithHmacSHA256(passphrase, SALT, 10000, 256)

private String getDeviceIdentifier() {
    String serial = Build.SERIAL;
    if (serial == null || serial.equals("unknown")) serial = DEFAULT_DEVICE_ID;
    return Integer.toHexString(serial.hashCode());
}
```

Todo es hardcodeado salvo `deviceId`, que depende de `Build.SERIAL`. En Android 8+
(API 26), `Build.SERIAL` devuelve `"unknown"` a apps sin el permiso privilegiado
`READ_PHONE_STATE`/`READ_PRIVILEGED_PHONE_STATE`, así que **cae a `DEFAULT_DEVICE_ID`**.
Por eso no hace falta el dispositivo: el `deviceId` es constante.

`deviceId = Integer.toHexString("DEFAULT_DEVICE_ID".hashCode())`. Reproduciendo el
`String.hashCode()` de Java:

```python
h=0
for c in "DEFAULT_DEVICE_ID": h=(31*h+ord(c)) & 0xFFFFFFFF
deviceId = format(h,'x')   # -> "c8e21b06"
```

---

## 3. Derivar la clave y descifrar el backup

```python
passphrase = "fluidvault_master_seed_2026" + "c8e21b06"
key = pbkdf2_hmac("sha256", passphrase.encode(),
                  bytes.fromhex("a915c3e00dbb5a55ba13d7cdaf3a126e"), 10000, 32)
# key = c70cf882eaf48e1da954f0105594fef19704aeae00e86756501957a033faa91a
```

`vault_backup.enc` está en formato `iv(12) || ciphertext || tag(16)` (AES-256-GCM,
según documenta `vault_decrypt.py`). Descifrado → JSON del vault:

```json
{"entries":[
  {"name":"Admin Portal","username":"admin","password":"Fl00d_G4t3s_0p3n!",...},
  {"name":"Corporate Email",...},
  {"name":"AWS Console",...}]}
```

El master password del admin es **`Fl00d_G4t3s_0p3n!`**.

---

## 4. De la credencial a la flag

`VaultApiClient.java` expone `POST /api/vault/admin` con `{"master_password": ...}`.
Enviando el password recuperado:

```http
POST /api/vault/admin
{"master_password":"Fl00d_G4t3s_0p3n!"}
```
```json
{"authenticated":true,"flag":"flag{a9f852a845bf784f}","role":"admin"}
```

---

## 5. Flag

```
flag{a9f852a845bf784f}
```

---

## 6. Causa raíz y remediación

**Causa raíz:** la "seguridad biométrica" es teatro. La clave de cifrado del vault se
deriva por completo de constantes en el binario (`SEED`, `SALT`) más un identificador de
dispositivo que en la práctica es una constante conocida. Cualquiera con el APK y el
backup reconstruye la clave sin el dueño ni su huella.

**Cómo se arregla:**

- **Anclar la clave a material que solo exista en hardware seguro:** derivar/envolver la
  clave del vault con una clave del **Android Keystore** con `setUserAuthenticationRequired(true)`
  (que el código genera en `initKeyStore()` pero **no usa** para el vault). La biometría
  debe ser condición necesaria para descifrar.
- **No derivar claves de seeds/salts hardcodeados** ni de identificadores de dispositivo
  (no secretos, a veces constantes). Usar una passphrase real del usuario con PBKDF2/Argon2
  de parámetros altos, o claves respaldadas por el TEE/StrongBox.
- Subir iteraciones y usar Argon2id en lugar de PBKDF2-10k.

**Lección de CTF (Mobile):** cuando un manager presume de biometría, revisa si la clave
de cifrado **realmente** depende de ella. A menudo el Keystore existe pero la clave del
dato se deriva por separado de constantes decompilables. `Build.SERIAL` en Android
moderno = `"unknown"` → cualquier ID derivado de él es una constante conocida.
