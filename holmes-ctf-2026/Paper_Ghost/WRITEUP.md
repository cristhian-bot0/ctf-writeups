# Holmes CTF 2026 — Sherlock 04: The False Employee ("Paper Ghost")

**Categoría:** DFIR / Windows forensics
**Evidencia:** `PaperGhost.zip` → colección KAPE (`Triage/C/...`) del equipo `CO-LT-0469`
**Entorno de análisis:** Linux (Arch), sin Windows ni herramientas Eric Zimmerman.
Todo se resuelve con `regipy`, `dissect.esedb` y `LnkParse3` desde un venv.

---

## 0. Resumen del caso

`DIOGENES` es el programa de fusión de inteligencia de la organización. **Elias Venn** (`evenn`,
contratista de IT, alias operativo *VON BORK*) dejó un pendrive sobre el escritorio de
**Clara Voss** (`cvoss`, Ministerial Briefing Office). El USB contenía un falso *driver update
package* que Voss ejecutó: `update.exe` abrió el micrófono y la webcam del portátil y exfiltró
~172 MB al C2.

El "botín" del espionaje fue el contenido del escritorio de Voss: la carpeta `DIOGENES_26`, con el
expediente de acceso de un desarrollador externo — **credenciales en claro incluidas**.

La colección es sólo de artefactos de registro/índice: **no hay `update.exe` en la evidencia**.
Toda la cadena se reconstruye a partir de:

| Artefacto | Ruta en el triage | Responde |
|---|---|---|
| Hive `SYSTEM` | `C/Windows/System32/config/SYSTEM` | primera conexión del USB, serial |
| Hive `SOFTWARE` | `C/Windows/System32/config/SOFTWARE` | nombre de activo del USB, zona horaria |
| `NTUSER.DAT` de cvoss | `C/Users/cvoss/NTUSER.DAT` | ejecución del payload (UserAssist), mic/webcam (ConsentStore) |
| `SRUDB.dat` | `C/Windows/System32/SRU/SRUDB.dat` | bytes exfiltrados al C2 |
| `Windows.edb` | `C/ProgramData/Microsoft/search/.../Windows.edb` | **contenido** de los PDF/CSV robados |

---

## 1. Preparación del entorno

Ninguna de las libs está en los repos de Arch; venv y a correr:

```bash
python3 -m venv pgvenv
./pgvenv/bin/pip install regipy dissect.esedb LnkParse3
```

`regipy` parsea hives sin necesitar transaction logs (los `.LOG1/.LOG2` están en el triage pero
no hacía falta replayarlos: ninguna clave relevante estaba en el log sucio).

---

## 2. El USB: primera conexión, serial y nombre de activo

### 2.1 Serial y primera conexión — `SYSTEM\ControlSet001\Enum\USBSTOR`

```python
from regipy.registry import RegistryHive
h = RegistryHive("Triage/C/Windows/System32/config/SYSTEM")
for ven in h.get_key(r"\ControlSet001\Enum\USBSTOR").iter_subkeys():
    for inst in ven.iter_subkeys():
        print(ven.name, "|", inst.name)
```

```
Disk&Ven_Lexar&Prod_USB_Flash_Drive&Rev_2.00 | RS200000000627E4&0
```

El serial aparece en la evidencia en dos formas, y la diferencia importa:

| Clave | Instancia | Comentario |
|---|---|---|
| `Enum\USBSTOR\Disk&Ven_Lexar&...` | `RS200000000627E4&0` | **la marca que deja el dispositivo** |
| `Enum\USB\VID_21C4&PID_0CD1` | `RS200000000627E4` | serial "limpio" del descriptor USB |

El `&0` es el sufijo de instancia que añade Windows al enumerar el dispositivo bajo USBSTOR. El
serial que el fabricante graba en el descriptor es `RS200000000627E4`, pero **la cadena que el
dispositivo deja escrita en el registro** — la *serial scar* que pide el reto — es la instancia
completa de USBSTOR, `RS200000000627E4&0`.

> Si el **segundo** carácter del serial fuera un `&`, sería un serial *generado* por Windows
> (el dispositivo no expone uno propio). No es el caso aquí: éste es un serial real de Lexar.

Para la **primera conexión** no vale el `lastwrite` de la clave (eso es la última modificación).
Hay que leer las *Device Properties* bajo `...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`:

| Valor | Propiedad | Contenido |
|---|---|---|
| `0064` | `DEVPKEY_Device_InstallDate` | 2026-08-19 15:35:50.428692 UTC |
| `0065` | `DEVPKEY_Device_FirstInstallDate` | 2026-08-19 15:35:50.428692 UTC |
| `0066` | `DEVPKEY_Device_LastArrivalDate` | 2026-08-19 15:51:06.432548 UTC |
| `0067` | `DEVPKEY_Device_LastRemovalDate` | 2026-08-19 15:51:06.557508 UTC |

`0064 == 0065` ⇒ el dispositivo se conectó **una sola vez** a esta máquina, a las
**2026-08-19 15:35:50 UTC**, y se retiró a las 15:51:06 UTC (unos 15 minutos de ventana).

`regipy` ya decodifica estos `FILETIME` a `datetime` con `tzinfo=UTC`, así que no hay conversión
manual que equivocar.

### 2.2 Nombre de activo — `SOFTWARE\Microsoft\Windows Portable Devices\Devices`

La organización etiqueta su hardware (`CO-LT-0469` es el portátil). El USB también tiene etiqueta,
y queda registrada como `FriendlyName` del dispositivo portátil:

```
SWD#WPDBUSENUM#_??_USBSTOR#DISK&VEN_LEXAR&PROD_USB_FLASH_DRIVE&REV_2.00#RS200000000627E4&0#{53F5...}
    FriendlyName = 'CO-USB-0091'
```

El serial del USBSTOR aparece embebido en el nombre de la clave, lo que ata el `CO-USB-0091` a
`RS200000000627E4` sin ambigüedad. (La otra entrada, `VTOYEFI`, es un Ventoy del propio analista /
ruido de la imagen base — descartada.)

---

## 3. El payload: ruta y ejecución (UserAssist)

`NTUSER.DAT` → `\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`.
Los nombres van cifrados con **ROT13** y el valor es una estructura de 72 bytes cuyo offset `0x3C`
es un `FILETIME` con la última ejecución:

```python
import codecs, struct
from regipy.registry import RegistryHive
h = RegistryHive("Triage/C/Users/cvoss/NTUSER.DAT")
base = r"\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
for g in h.get_key(base).iter_subkeys():
    for v in h.get_key(base + "\\" + g.name + "\\Count").get_values():
        name = codecs.decode(v.name, "rot13")
        blob = v.value
        run, ts = struct.unpack("<I", blob[4:8])[0], struct.unpack("<Q", blob[60:68])[0]
        ...
```

Resultado relevante:

```
E:\CO-LT-0469 update package\update.exe   run_counter=1   2026-08-19T15:36:25.705000+00:00
```

Tres lecturas de golpe:

- **Ruta completa del payload:** `E:\CO-LT-0469 update package\update.exe`
- **Ejecución:** `2026-08-19 15:36:25 UTC` — **35 segundos** después de enchufar el USB.
- `run_counter = 1`: se ejecutó exactamente una vez.

La carpeta del USB se llama igual que el activo de la víctima (`CO-LT-0469 update package`): es
*spear-phishing físico*, el pendrive estaba preparado para ese portátil concreto. El PDF señuelo
`Driver Update Package.pdf` (ver §6) daba instrucciones para que Voss lo abriera.

---

## 4. Micrófono y webcam — CapabilityAccessManager

Windows 10/11 registra el uso de mic/cámara por aplicación en:

```
NTUSER\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\<cap>\NonPackaged\<app>
```

Para binarios *non-packaged* la ruta se codifica sustituyendo `\` por `#`. Los valores
`LastUsedTimeStart` / `LastUsedTimeStop` son `FILETIME` (`0` en Stop = todavía en uso).

```python
start = vals["LastUsedTimeStart"]; stop = vals["LastUsedTimeStop"]
dur = (stop - start) / 1e7      # FILETIME son unidades de 100 ns
```

```
[microphone] NonPackaged\E:#CO-LT-0469 update package#update.exe
     start=2026-08-19 15:38:08.113179  stop=2026-08-19 15:41:03.258924  dur=175.1457449 s
[webcam]     NonPackaged\E:#CO-LT-0469 update package#update.exe
     start=2026-08-19 15:42:28.681431  stop=2026-08-19 15:44:35.661981  dur=126.9805499 s
```

- **Inicio de captura de micrófono:** `2026-08-19 15:38:08 UTC` (103 s después de ejecutarse).
- **Duración del stream de webcam:** `126.98 s` (≈ **127 segundos**).

Nótese el orden: primero micrófono (~2 min 55 s), luego webcam (~2 min 7 s). El malware no
grabó en paralelo.

> El `ConsentStore` del hive `SOFTWARE` (equivalente a nivel máquina) está vacío para este
> binario: sólo aparece en el perfil de `cvoss`, lo que confirma que corrió en su contexto de
> usuario, sin privilegios elevados.

---

## 5. Exfiltración al C2 — SRUM

`SRUDB.dat` es una base ESE. La tabla de uso de red es
`{973F5D5C-1D90-4944-BE8E-24B94231A174}`; los campos `AppId`/`UserId` son índices a
`SruDbIdMapTable`, donde los nombres están en **UTF-16LE**.

```python
from dissect.esedb import EseDB
db = EseDB(open("Triage/C/Windows/System32/SRU/SRUDB.dat", "rb"))
idmap = {r.get("IdIndex"): r.get("IdBlob").decode("utf-16-le").rstrip("\x00")
         for r in db.table("SruDbIdMapTable").records() if isinstance(r.get("IdBlob"), bytes)}
```

Agregando `BytesSent` por aplicación:

```
sent=   200906107  recv=  2198922531  app=None                                              (ruido/host)
sent=   172064531  recv=      615595  app=\device\harddiskvolume5\co-lt-0469 update package\update.exe
sent=     6688857  recv=   330747273  app=DoSvc
sent=     6301290  recv=    24042221  app=...\msedge.exe
```

`update.exe` envió **172 064 531 bytes** y recibió apenas 615 KB: ratio ~280:1, firma inequívoca
de **exfiltración**, no de una descarga de actualización (que sería lo contrario).

- **MB decimales salientes:** `172064531 / 1 000 000` = **172.064531 MB**

> Detalle: el `AppId` apunta a `harddiskvolume5`, es decir, el proceso se ejecutó **directamente
> desde el USB** (volumen `E:`), nunca se copió al disco del sistema. Por eso no hay binario en el
> triage ni entradas de Prefetch/Amcache para él en el disco local.

---

## 6. La joya: credenciales del desarrollador (Windows Search index)

Ésta es la pregunta interesante, porque **el contenido robado no está en la evidencia**: la
carpeta `C:\Users\cvoss\Desktop\DIOGENES_26\` no se recolectó, sólo hay `.lnk` en `Recent/`
apuntando a sus ficheros (`EXT-0419.lnk`, `IT_SUPPORT.lnk`, `Schedule.lnk`,
`Driver Update Package.lnk`).

La solución es **Windows Search**: el indexador guarda en `Windows.edb` un extracto del texto de
cada documento indexado, en la propiedad `System.Search.AutoSummary` de la tabla
`SystemIndex_PropertyStore`. Es decir, **hay copia parcial del contenido de los PDF dentro del
índice**, aunque los PDF ya no estén.

```python
from dissect.esedb import EseDB
db = EseDB(open("Triage/C/ProgramData/Microsoft/search/data/applications/windows/Windows.edb", "rb"))
t = db.table("SystemIndex_PropertyStore")
cols = [c.name for c in t.columns]
for r in t.records():
    vals = {c: r.get(c) for c in cols}
    path = str(vals.get("4447-System_ItemPathDisplay", ""))
    if "DIOGENES_26" in path:
        print(path, "\n", vals.get("4625-System_Search_AutoSummary"), "\n")
```

> Los nombres de columna llevan el PID delante (`4625-System_Search_AutoSummary`,
> `4447-System_ItemPathDisplay`, ...). Un `strings` sobre el `.edb` también saca fragmentos, pero
> el texto de los PDF está almacenado en **UTF-8 comprimido por columna**, no en UTF-16, así que
> el volcado UTF-16 que hice primero (`edb_u16.txt`) sólo sacaba nombres de fichero y URLs — por
> ahí no se llega. Hay que parsear la tabla de verdad.

Salen 21 filas. El primer pivote útil es el CSV de contratistas:

```
C:\Users\cvoss\Desktop\DIOGENES_26\DIOGENES_Contractor_Assignments.csv
Contractor ID,Name,Title,Unit,Assigned Task,Repository,Assignment Date,Clearance,Status,Supervisor
EXT-0419,Tom Ainsworth,Software Developer,DIOGENES Ticketing Support,Parse and migrate
  DIOGENES incident tickets into the fusion queue,parse_diogenese_tickets,2026-07-14,EXT-3,Active,
  OBERSTEIN service path
EXT-0420,—,UI Developer,...
```

`EXT-0419 / Tom Ainsworth` es el único **Software Developer** cuya tarea son literalmente los
*tickets de DIOGENES*. Y existe un `EXT-0419.pdf` en la misma carpeta:

```
C:\Users\cvoss\Desktop\DIOGENES_26\EXT-0419.pdf

PERSONNEL & ACCESS FILE — EXTERNAL CONTRACTOR
DIOGENES Ticketing Support          Classification: OFFICIAL-SENSITIVE
Name:                Tom Ainsworth
Title:               Software Developer, DIOGENES Ticketing Support (External Contractor)
Contractor ID:       EXT-0419
Internal server:     srv-diogenes-tickets-01.internal
Username:            tainsworth
Password:            D10g3n3s_T1ck3ts#2026
Access scope:        EXT-3 (ticketing host only)
Assigned repository: parse_diogenese_tickets
```

- **Credenciales expuestas:** `tainsworth:D10g3n3s_T1ck3ts#2026`

El `Schedule.pdf` de Voss cierra la narrativa — ella misma tenía anotado el riesgo:

```
11:30  External Contractor Task Review — DIOGENES
       - EXT-0419 Tom Ainsworth — parse_diogenese_tickets
       NOTE: Ainsworth has direct access to the ticketing host.
       Confirm his credentials are still scoped to EXT-3 only.
```

Y el `IT_SUPPORT.pdf` identifica al insider:

```
CONTRACTOR ONBOARDING RECORD — IT SUPPORT
Full name:         Elias Venn        Contractor ID: EXT-0431
Role:              IT Support (Field)
Assigned floor:    Floor 4 — Ministerial Briefing Office
Delivery address:  Unit 14, Silvertown East Yard (per contractor file)
First day on site: 30 July 2026
```

Mientras que `Driver Update Package.pdf` es el señuelo que acompañaba al USB:

```
BRIEFING NOTES — DRIVER UPDATE PACKAGE
For asset CO-LT-0469 (user: cvoss)
Files included: - update.exe
1. Insert the USB device into asset CO-LT-0469.
2. Open Q4_Briefing_Notes to begin the update.
4. Return the USB to the Floor 4 spares cabinet (Cabinet 4C).
```

Documento hecho a medida para Voss, con su nombre de usuario y su número de activo. El señuelo
llegó al escritorio *antes* que el USB.

---

## 7. Nota sobre zonas horarias

`SOFTWARE\...\TimeZoneInformation`:

```
TimeZoneKeyName = 'Pacific Standard Time'
Bias = 480        (UTC-8)
ActiveTimeBias = 420   (UTC-7, horario de verano activo en agosto)
```

**Todos los timestamps de este writeup están en UTC**, que es como se almacenan nativamente los
`FILETIME` del registro. La hora local del equipo en el momento del incidente es UTC-7:

| Evento | UTC | Local (PDT) |
|---|---|---|
| USB conectado | 15:35:50 | 08:35:50 |
| `update.exe` ejecutado | 15:36:25 | 08:36:25 |
| Micrófono ON | 15:38:08 | 08:38:08 |
| Webcam ON | 15:42:28 | 08:42:28 |
| USB retirado | 15:51:06 | 08:51:06 |

Encaja con el escenario: a primera hora de la mañana, justo cuando Voss prepara el *morning brief*.

---

## 8. Línea temporal reconstruida (UTC, 2026-08-19)

```
15:35:50   USB Lexar RS200000000627E4 ("CO-USB-0091") conectado por primera vez → E:
15:36:25   cvoss ejecuta E:\CO-LT-0469 update package\update.exe   (35 s después)
15:38:08   update.exe abre el MICRÓFONO
15:41:03   micrófono cerrado                                        (175.15 s)
15:42:28   update.exe abre la WEBCAM
15:44:35   webcam cerrada                                           (126.98 s)
  ~        172.06 MB salientes hacia el C2 (SRUM, volumen 5 = el propio USB)
15:51:06   USB retirado — nunca se volvió a conectar
```

---

## 9. Respuestas

| # | Pregunta | Respuesta |
|---|---|---|
| 1 | Primera conexión del USB | `2026-08-19 15:35:50` (UTC) |
| 2 | Serial del USB | `RS200000000627E4&0` (instancia USBSTOR, con sufijo) |
| 3 | Ruta completa del payload | `E:\CO-LT-0469 update package\update.exe` |
| 4 | Ejecución del payload | `2026-08-19 15:36:25` (UTC) |
| 5 | Nombre de activo del USB | `CO-USB-0091` |
| 6 | Inicio de captura de micrófono | `2026-08-19 15:38:08` (UTC) |
| 7 | Duración del stream de webcam | `127` segundos (exacto: 126.9805499) |
| 8 | MB (decimales) enviados al C2 | `172.064531` |
| 9 | Credenciales del developer de tickets DIOGENES | `tainsworth:D10g3n3s_T1ck3ts#2026` |

---

## 10. Lecciones

1. **`Windows.edb` es una copia de seguridad accidental del contenido de los documentos.**
   Cuando el fichero original no está en la evidencia, `System.Search.AutoSummary` suele tener los
   primeros ~500 caracteres. Es el artefacto más infravalorado de un triage KAPE.
2. **Serial USB: ojo con el sufijo `&N`.** Existen dos cadenas — la instancia de `USBSTOR`
   (`RS200000000627E4&0`) y el serial del descriptor bajo `Enum\USB` (`RS200000000627E4`). Cuando
   la pregunta es "qué serial *dejó* el dispositivo", quieren la primera, literal del registro.
3. **`InstallDate`/`FirstInstallDate` (`0064`/`0065`) sobre el `lastwrite`** para fechar la primera
   conexión: el `lastwrite` sólo te da la última vez que se tocó la clave.
4. **El ratio sent/recv de SRUM distingue exfiltración de actualización.** 172 MB out vs 0.6 MB in
   no es un instalador descargando nada.
5. El `AppId` de SRUM con `harddiskvolume5` delata que el binario **nunca tocó el disco local** —
   por eso no hay Prefetch ni Amcache que buscar, y perseguirlos es tiempo perdido.
