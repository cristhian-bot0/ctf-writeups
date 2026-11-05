# RootWars 2026 — enHacke CTF · Writeup

**Autor:** ElPRESI · **Plataforma:** CTFd (ctf.enhacke.com) · **Flag:** `NHK{[REDACTED]}`

**93 retos** · ~**12828 pts**.

---

## Iniciación  (1)

### [95] Inicio — 10 pts

> Bienvenido a **RootWars 2026**. Este reto no tiene truco: es solo para que pruebes cómo se envía una bandera en la plataforma antes de que empiece el resto.

**Técnica:** Flag de ejemplo.

**Flag:** `NHK{[REDACTED]}`

---

## Misceláneo / Trivia  (40)

### [111] El portero del candado — 10 pts

> Todo sitio con candado entra por la misma puerta TCP. ¿Qué número lleva?

**Técnica:** HTTPS → 443.

**Flag:** `NHK{[REDACTED]}`

### [112] La libreta del mundo — 10 pts

> Sin mí escribirías números en el navegador. Soy la libreta que traduce nombres en direcciones. ¿Cuál es mi sigla de tres letras?

**Técnica:** DNS traduce nombres a IPs.

**Flag:** `NHK{[REDACTED]}`

### [113] Caparazón seguro — 10 pts

> Reemplazó a Telnet para que nadie espiara tus comandos. ¿Por qué puerto TCP escucha por defecto?

**Técnica:** SSH → 22.

**Flag:** `NHK{[REDACTED]}`

### [114] El cartero antiguo — 15 pts

> Mucho antes de los chats, un cartero llevaba tus cartas de servidor en servidor, sin sobre cifrado por defecto. ¿Por qué puerto TCP trabaja el SMTP clásico?

**Técnica:** SMTP → 25.

**Flag:** `NHK{[REDACTED]}`

### [115] Más casas que granos de arena — 15 pts

> Si IPv4 es un barrio de 32 bits, ¿de cuántos bits es su sucesor IPv6?

**Técnica:** IPv6 → 128 bits.

**Flag:** `NHK{[REDACTED]}`

### [116] El pingüino tiene padre — 15 pts

> Un estudiante finlandés publicó en 1991 «solo un pasatiempo». Hoy mueve servidores, teléfonos y satélites. ¿Quién es? (apellido)

**Técnica:** Linus Torvalds.

**Flag:** `NHK{[REDACTED]}`

### [117] La puerta favorita del ransomware — 20 pts

> Cuando un operador de ransomware encuentra esta puerta abierta a Internet, ya ganó la mitad. Es el Escritorio Remoto de Windows. ¿Qué puerto TCP usa?

**Técnica:** RDP → 3389.

**Flag:** `NHK{[REDACTED]}`

### [143] Hexadecimal con sombrero — 20 pts

> Convierte `4E 48 4B` de hexadecimal a texto ASCII.

**Técnica:** Hex 4E484B='NHK'.

**Flag:** `NHK{[REDACTED]}`

### [144] Los iguales del final — 20 pts

> Decodifica: `RW5IYWNrZQ==`

**Técnica:** base64='EnHacke'.

**Flag:** `NHK{[REDACTED]}`

### [145] Solo dos símbolos — 20 pts

> ¿Cuánto es `101010` (binario) en decimal?

**Técnica:** 101010b=42.

**Flag:** `NHK{[REDACTED]}`

### [146] Voz binaria — 25 pts

> Decodifica: `01001000 01101111 01101100 01100001`

**Técnica:** binario='Hola'.

**Flag:** `NHK{[REDACTED]}`

### [147] Trece vueltas — 25 pts

> Decodifica: `Ebbgjnef` (es un nombre propio, escríbelo en minúsculas).

**Técnica:** ROT13='rootwars'.

**Flag:** `NHK{[REDACTED]}`

### [118] Adiós, DES — 30 pts

> En 2001, el NIST eligió a un algoritmo belga, de nombre impronunciable, para jubilar a DES. ¿Con qué sigla de tres letras lo conocemos hoy?

**Técnica:** AES reemplazó a DES (2001).

**Flag:** `NHK{[REDACTED]}`

### [119] Huella larga — 30 pts

> SHA-256 produce una huella cuyo nombre ya delata su tamaño. ¿Cuántos bits tiene?

**Técnica:** SHA-256 → 256 bits.

**Flag:** `NHK{[REDACTED]}`

### [120] Todos los relojes en hora — 30 pts

> Sin él, los logs de dos servidores no pueden contar la misma historia. Es el protocolo de tres letras que sincroniza relojes, por UDP 123. ¿Cuál es?

**Técnica:** NTP (UDP 123).

**Flag:** `NHK{[REDACTED]}`

### [148] Telégrafo — 30 pts

> Decodifica: `.-. --- --- - .-- .- .-. ...`

**Técnica:** Morse='ROOTWARS'.

**Flag:** `NHK{[REDACTED]}`

### [149] El cero que no es cero — 30 pts

> En la tabla ASCII, ¿qué número decimal tiene el carácter `0`?

**Técnica:** ASCII '0'=48.

**Flag:** `NHK{[REDACTED]}`

### [121] La huella que cayó en 2017 — 40 pts

> Un equipo de Google y el CWI mostró en 2017 la primera colisión práctica («SHAttered») de esta función. ¿De cuántos bits es su huella?

**Técnica:** SHAttered rompió SHA-1 (160 bits, 2017).

**Flag:** `NHK{[REDACTED]}`

### [122] El perro de tres cabezas — 40 pts

> En la mitología custodiaba la puerta del Hades; en el dominio, custodia los tickets. ¿Qué puerto estándar usa Kerberos?

**Técnica:** Kerberos → 88.

**Flag:** `NHK{[REDACTED]}`

### [123] Corazón sangrante — 40 pts

> Una extensión de latido de OpenSSL dejó leer memoria de los servidores sin dejar rastro. ¿En qué año se divulgó?

**Técnica:** Heartbleed → 2014.

**Flag:** `NHK{[REDACTED]}`

### [124] Quien llama y no entra — 50 pts

> Un SOC que no escucha los intentos fallidos de sesión es un SOC sordo. ¿Qué Event ID de Windows registra un inicio de sesión fallido?

**Técnica:** Event ID 4625 (logon fallido).

**Flag:** `NHK{[REDACTED]}`

### [125] Cuando por fin entra — 50 pts

> Después de mil golpes en la puerta, alguien por fin entró. ¿Qué Event ID de Windows registra un inicio de sesión exitoso?

**Técnica:** Event ID 4624 (logon ok).

**Flag:** `NHK{[REDACTED]}`

### [126] Quiero llorar — 50 pts

> Mayo de 2017: hospitales detenidos y pantallas rojas pidiendo bitcoin. El gusano usaba EternalBlue. ¿Cómo se llamaba?

**Técnica:** WannaCry (2017).

**Flag:** `NHK{[REDACTED]}`

### [127] El mapa del adversario — 60 pts

> MITRE publica una matriz de tácticas y técnicas de atacantes reales. Su nombre lleva un símbolo y parece una jugada de ajedrez. ¿Cuál es? (sin espacios)

**Técnica:** MITRE ATT&CK.

**Flag:** `NHK{[REDACTED]}`

### [150] La eñe cuesta — 60 pts

> En UTF-8, ¿cuántos bytes ocupa el carácter `ñ`?

**Técnica:** 'ñ' UTF-8 = 2 bytes.

**Flag:** `NHK{[REDACTED]}`

### [128] Cuatro eles — 80 pts

> Diciembre de 2021: una biblioteca de registros de Java dejó ejecutar código remoto con solo escribir una cadena. ¿Qué identificador CVE tiene Log4Shell?

**Técnica:** Log4Shell = CVE-2021-44228.

**Flag:** `NHK{[REDACTED]}`

### [129] Cincuenta y… algo — 100 pts

> DES usa llaves de 64 bits, pero ocho de ellas son solo paridad. ¿Cuántos bits efectivos tiene realmente su llave?

**Técnica:** DES → 56 bits efectivos.

**Flag:** `NHK{[REDACTED]}`

### [130] Un grito en el 514 — 100 pts

> Los equipos de red gritan sus logs a quien quiera escuchar, sin acuse de recibo. ¿Qué puerto UDP usa syslog por defecto?

**Técnica:** syslog → UDP 514.

**Flag:** `NHK{[REDACTED]}`

### [131] Mil cámaras, un apagón — 100 pts

> Octubre de 2016: cámaras IP con contraseñas de fábrica tumbaron a un proveedor de DNS y media Internet se quedó a oscuras. ¿Cómo se llama la botnet?

**Técnica:** Botnet Mirai (2016).

**Flag:** `NHK{[REDACTED]}`

### [132] Gusano de laboratorio — 100 pts

> Dañó centrifugadoras de Natanz sin que los operadores lo notaran. Es el primer gusano famoso diseñado para sabotear procesos físicos. ¿Su nombre?

**Técnica:** Stuxnet (Natanz).

**Flag:** `NHK{[REDACTED]}`

### [133] El anzuelo en la bandeja — 150 pts

> En ATT&CK, la técnica que comienza con un correo con anzuelo tiene un identificador T####. ¿Cuál es el de Phishing?

**Técnica:** Phishing = T1566.

**Flag:** `NHK{[REDACTED]}`

### [134] Intérprete con mala fama — 150 pts

> PowerShell, bash, cmd, Python… En ATT&CK, abusar de ellos tiene un identificador T####. ¿Cuál es el de Command and Scripting Interpreter?

**Técnica:** Command&Scripting Interpreter = T1059.

**Flag:** `NHK{[REDACTED]}`

### [135] El oso elegante — 150 pts

> Un oso de modales finos entró a servidores de partidos políticos en 2016. En MITRE se cataloga como APT28. ¿Cuál es su apodo en inglés? (dos palabras)

**Técnica:** APT28 = Fancy Bear.

**Flag:** `NHK{[REDACTED]}`

### [136] Noventa y seis — 200 pts

> El NIST recomienda un valor de longitud fija para el IV/nonce de AES-GCM, porque se procesa de forma más eficiente y evita más riesgos. ¿Cuántos bits?

**Técnica:** IV AES-GCM = 96 bits.

**Flag:** `NHK{[REDACTED]}`

### [137] El perro que muerde tickets — 200 pts

> Una cuenta de servicio con una contraseña débil y un SPN. Alguien pide su ticket TGS y se va a casa a romperlo con calma. ¿Cómo se llama la técnica?

**Técnica:** Kerberoasting.

**Flag:** `NHK{[REDACTED]}`

### [138] El nombre oficial del corazón — 200 pts

> Heartbleed tiene un CVE de cuatro cifras en el sufijo. ¿Cuál es? (formato CVE-AAAA-NNNN)

**Técnica:** Heartbleed = CVE-2014-0160.

**Flag:** `NHK{[REDACTED]}`

### [139] Dos letras de un ingeniero — 250 pts

> Todo ejecutable de Windows empieza con los bytes `4D 5A` («MZ»). Son las iniciales de un ingeniero que trabajó en MS-DOS. ¿Cuál es su apellido?

**Técnica:** MZ = Mark Zbikowski.

**Flag:** `NHK{[REDACTED]}`

### [140] El hash del silencio — 250 pts

> ¿Qué obtienes al calcular el MD5 de la cadena vacía? (32 caracteres hexadecimales)

**Técnica:** MD5('')=d41d8cd98f00b204e9800998ecf8427e.

**Flag:** `NHK{[REDACTED]}`

### [141] Pesca en la memoria — 250 pts

> Un clásico volcador de credenciales usa un módulo y un comando para sacar contraseñas y hashes de sesiones desde la memoria de LSASS. ¿Cuál es el comando completo `módulo::comando`

**Técnica:** mimikatz sekurlsa::logonpasswords.

**Flag:** `NHK{[REDACTED]}`

### [142] Eterno azul — 250 pts

> EternalBlue explotaba una vulnerabilidad de SMBv1 corregida en el boletín MS17-010. ¿Cuál es su identificador CVE?

**Técnica:** EternalBlue = CVE-2017-0144.

**Flag:** `NHK{[REDACTED]}`

---

## Crypto  (15)

### [96] Ave, Hidra — 50 pts

> Un viejo general romano apareció en la bandeja de entrada del SOC. Jura que no sabe escribir de otra forma: toma cada letra y la manda de viaje, siempre la misma distancia. Hoy dej

**Técnica:** Cesar shift 11. 'Ave Hidra te saludamos'.

**Flag:** `NHK{[REDACTED]}`

### [97] Espejo, espejito — 75 pts

> La Hidra firma sus notas frente a un espejo extraño: la primera letra del abecedario regresa convertida en la última, la segunda en la penúltima… En la sala nadie logra leer el car

**Técnica:** Atbash (A<->Z).

**Flag:** `NHK{[REDACTED]}`

### [98] Capas de cebolla — 100 pts

> La Hidra odia que la lean a la primera. Cada vez que crees haber llegado, alguien te abrió otra puerta. Quien llora pelando, avanza.

**Técnica:** Capas: base64 -> base32 -> hex -> base64 -> ASCII.

**Flag:** `NHK{[REDACTED]}`

### [99] La contraseña que nunca debió salir — 100 pts

> Entre los restos de un servidor de la Hidra apareció esta línea. Quien guarda secretos con una función tan vieja y sin sal merece una lección. La bandera es `NHK{[REDACTED]}`

### [100] Doble turno — 150 pts

> El implante de la Hidra cifra sus órdenes con una llave corta que se repite como un mantra. Cada orden es un traje distinto, pero el sastre es siempre el mismo. Hoy dejó una orden 

**Técnica:** XOR clave repetida 'HYDRA' (crib NHK{[REDACTED]}`

### [101] El idioma de la capucha — 175 pts

> Un informe del turno de noche se filtró. La Hidra lo reescribió con una palabra secreta que se repite como una cantinela. La vieja escuela decía que este cifrado era «indescifrable

**Técnica:** Vigenere clave 'hidra' (frecuencias ES).

**Flag:** `NHK{[REDACTED]}`

### [102] La valla de tres hilos — 175 pts

> Los mensajes de la Hidra suben y bajan por una valla como un pájaro nervioso: una letra en el hilo de arriba, la siguiente en el del medio, la siguiente abajo… y de vuelta.

**Técnica:** Rail fence 3 rieles.

**Flag:** `NHK{[REDACTED]}`

### [103] Columnas fuera de formación — 200 pts

> Una compañía de seis columnas desfiló por el patio del SOC. Nadie respetó el orden de la lista y el cartel con la frase quedó hecho trizas. Alguien rellenó la cola con equis.

**Técnica:** Transposicion columnar 6 col, relleno X.

**Flag:** `NHK{[REDACTED]}`

### [104] Candado de papel — 200 pts

> Un candado moderno con tornillos de plastilina: dos primos que se creyeron grandes. Descifra `c` para obtener el entero `m`; la bandera es `NHK{[REDACTED]}`.

**Técnica:** RSA: n=520007380592396169957119 factoriza; m=68300894909150264.

**Flag:** `NHK{[REDACTED]}`

### [105] Tres emisarios, un secreto — 300 pts

> La Hidra mandó el mismo mensaje a tres cómplices, cada uno con su propio candado, pero todos con la misma llave pública pequeña. «Pequeña» fue su error.

**Técnica:** Hastad e=3: CRT de (c1,c2,c3) mod n1*n2*n3 -> m^3; raiz cubica entera exacta -> ASCII.

**Flag:** `NHK{[REDACTED]}`

### [109] La firma que se repitió — 350 pts

> Un bot de la Hidra firma cada orden con ECDSA sobre una curva elíptica propia. Interceptaste dos órdenes del mismo bot y algo en sus firmas se repite: el número `r`. Eso nunca debe

**Técnica:** Nonce reuse ECDSA: z=sha256(msg) mod q; k=(z1-z2)/(s1-s2); d=(s1*k-z1)/r mod q=8991051159748133173069073113042. Verificado d*G==Q.

**Flag:** `NHK{[REDACTED]}`

### [106] El cerrojo con llave de bolsillo — 400 pts

> Su exponente público es un monstruo del tamaño del propio módulo, pero el privado cabe en un bolsillo. Quien apuró la llave para descifrar más rápido dejó la puerta abierta.

**Técnica:** Wiener: convergentes de e/n; d=937305240707822346291023899014943903; m=pow(c,d,n) -> ASCII.

**Flag:** `NHK{[REDACTED]}`

### [107] El token que sueña igual — 450 pts

> El C2 de la Hidra fabrica «tokens de sesión aleatorios» con una fórmula barata: cada token nace del anterior. Interceptaste doce. Dime cuál será el siguiente; la bandera es `NHK{[REDACTED]}`

### [108] El apretón de manos con trampa — 499 pts

> Dos bots de la Hidra acuerdan una llave en público, sin verse. Eligieron el primo equivocado: uno cuyo pasado está hecho de números pequeños. Calcula la llave compartida `s = g^(ab

**Técnica:** DH con primo liso (p-1 smooth). Pohlig-Hellman para hallar a=dlog_g(A); s=B^a mod p.
s = 115546342658475353241005691028685014807964187289
flag = NHK{[REDACTED]} = NHK{[REDACTED]}

**Flag:** `NHK{[REDACTED]}`

### [110] El oráculo que solo dice sí o no — 549 pts

> Un servicio de la Hidra guarda un mensaje cifrado y nunca lo muestra. Pero si le envías cualquier texto cifrado (en hexadecimal, por línea), te dice si el relleno al final «tiene s

**Técnica:** CBC padding oracle (nc :2231, formato hex iv||ct, resp OK/BAD, conexion persistente).
Ataque de Vaudenay byte a byte, pipelineado 256/ráfaga. Plaintext: NHK{[REDACTED]}

**Flag:** `NHK{[REDACTED]}`

---

## Stego  (9)

### [180] Postal de la Hidra — 50 pts

> Una postal llegó al buzón del SOC sin remitente ni sello. La imagen es preciosa, pero toda cámara susurra algo cuando dispara: cuándo, con qué, y a veces algo más. La Hidra jura qu

**Técnica:** EXIF UserComment.

**Flag:** `NHK{[REDACTED]}`

### [181] Comprobante sospechoso — 75 pts

> Contabilidad recibió un «comprobante de pago» en PDF y nadie logra abrirlo. El visor protesta, el antivirus bosteza. A veces la etiqueta de la caja no dice lo que hay dentro.

**Técnica:** Polyglot: extension PDF pero magic PNG; flag en la imagen.

**Flag:** `NHK{[REDACTED]}`

### [182] Silencio que pesa — 100 pts

> La Hidra mandó un comunicado a la prensa. Se lee limpio, pero el archivo pesa más de lo que dicen sus palabras. Hay tinta que no se ve, aunque ocupa espacio.

**Técnica:** Zero-width (U+200B=0,U+200C=1) binario.

**Flag:** `NHK{[REDACTED]}`

### [183] Dos en uno — 100 pts

> Una foto de la sala de servidores circula por el chat de TI. Parece una sola imagen, pero la Hidra tiene más de una cabeza, y a veces una se esconde pegada detrás de otra.

**Técnica:** ZIP anexado tras FFD9 (nota.txt).

**Flag:** `NHK{[REDACTED]}`

### [184] Bajo la piel — 125 pts

> En esta imagen todo parece en orden: los colores son los mismos y la forma también. Pero cada píxel guarda el último suspiro de su color, y la Hidra lo usa como cajón secreto.

**Técnica:** LSB de RGB.

**Flag:** `NHK{[REDACTED]}`

### [185] Informe a medias — 150 pts

> El informe llegó dañado: ningún visor lo abre. Alguien le cambió una medida y ya no cuadra. Arregla lo que se rompió y lee el pie del documento, donde siempre va lo importante.

**Técnica:** IHDR altura 400->600 (CRC fix); flag al pie.

**Flag:** `NHK{[REDACTED]}`

### [186] Voz de la serpiente — 175 pts

> Alguien dejó una breve grabación en el buzón de voz. Suena a estática, a siseo de serpiente. Pero hay cosas que no se oyen: se miran.

**Técnica:** Espectrograma WAV.

**Flag:** `NHK{[REDACTED]}`

### [188] Doble capa — 275 pts

> Este escudo parece sólido, pero tiene una capa de transparencia que nadie mira: el canal alfa. Y lo que esconde ahí tampoco se deja leer a la primera, porque alguien lo revolvió co

**Técnica:** LSB canal alfa XOR 'HYDRA'.

**Flag:** `NHK{[REDACTED]}`

### [189] Bajo la superficie — 325 pts

> Esta pista de audio no esconde dibujos en el espectro: esconde datos de verdad, uno por muestra, en el lugar donde nadie los busca. Suena casi a música; no lo es del todo.

**Técnica:** LSB de muestras PCM.

**Flag:** `NHK{[REDACTED]}`

---

## OSINT  (13)

### [190] El registro que no debió quedar público — 50 pts

> La Hidra registró un dominio de respaldo y alguien olvidó activar la privacidad WHOIS. A veces el dato más valioso de un dominio no está en su contenido, sino en quién lo registró.

**Técnica:** WHOIS Registrant Organization.

**Flag:** `NHK{[REDACTED]}`

### [196] El operador descuidado — 60 pts

> Un operador de la Hidra tiene un perfil público en una red social ficticia. Publica de madrugada y cree que nadie lee con atención. Nosotros sí.

**Técnica:** Acrostico posts: E-S-C-A-M-A.

**Flag:** `NHK{[REDACTED]}`

### [193] El memo que nadie leyó — 70 pts

> Una transacción de la billetera operativa de la Hidra incluye un campo OP_RETURN: espacio libre para dejar un mensaje arbitrario en la cadena. Nadie revisa ese campo. Nosotros sí.

**Técnica:** OP_RETURN hex -> ASCII.

**Flag:** `NHK{[REDACTED]}`

### [191] Subdominios bajo la alfombra — 90 pts

> Un volcado de enumeración de subdominios del dominio operativo de la Hidra circula por el SOC. Entre decenas de registros normales (A, SPF, DMARC), uno de los TXT no es lo que apar

**Técnica:** TXT flag-cache base32 -> flag.

**Flag:** `NHK{[REDACTED]}`

### [202] La página que creyó estar limpia — 150 pts

> La página personal de un operador no tiene nada a la vista: un par de frases y ya. Pero lo que el navegador renderiza no es todo lo que el archivo contiene.

**Técnica:** meta name=internal-ref en el <head>.

**Flag:** `NHK{[REDACTED]}`

### [192] El repositorio que olvidaron borrar — 160 pts

> Un servidor de la Hidra expuso por error su directorio `.git/` (sin el código de la app, solo el repo). Borrar un archivo del árbol de trabajo no borra su historia.

**Técnica:** git: secrets.txt borrado, blob en historial (git rev-list --all).

**Flag:** `NHK{[REDACTED]}`

### [197] ¿Desde dónde disparó? — 180 pts

> Una foto sin ningún texto apareció en el dispositivo de un operador. La imagen no dice nada, pero la cámara que la tomó sí: guardó coordenadas GPS exactas del lugar.

**Técnica:** NHK{[REDACTED]} — GPS EXIF -12.1211,-77.0282 -> Parque Kennedy (Miraflores).

**Flag:** `NHK{[REDACTED]}`

### [194] La billetera de la tesorería — 200 pts

> Varias transacciones de la Hidra muestran sus entradas (inputs). La heurística de 'propiedad común de entradas' dice que si varias direcciones gastan juntas en una misma transacció

**Técnica:** common-input-ownership: change addr repetida, note base64.

**Flag:** `NHK{[REDACTED]}`

### [200] El commit huérfano — 280 pts

> Otro repositorio `.git` expuesto de la Hidra — pero esta vez el operador fue más cuidadoso: deshizo su commit con `git reset --hard` y limpió el reflog. `git log --all` no muestra 

**Técnica:** git fsck dangling commit b3fc0cb -> creds.env.

**Flag:** `NHK{[REDACTED]}`

### [198] El mismo usuario, dos máscaras — 300 pts

> Dos perfiles públicos, en dos redes distintas, con nombres de usuario totalmente diferentes. ¿Son la misma persona? Compara horarios de publicación y manías de escritura antes de c

**Técnica:** Correlacion: typo 'plataforna' + 03:14; flag en pixelwall.

**Flag:** `NHK{[REDACTED]}`

### [195] Sigue el dinero — 350 pts

> Los fondos de la tesorería se movieron en varios saltos antes de llegar a una billetera fría. Cada transacción tiene una salida principal y una señuelo. Sigue el rastro correcto ha

**Técnica:** Seguir salida principal hasta COLDWALLET, label base64.

**Flag:** `NHK{[REDACTED]}`

### [201] Señal fragmentada en la cadena — 400 pts

> La tesorería de la Hidra manda un mensaje escondido entre decenas de transacciones de relleno. No está en una sola: está repartido, en orden, usando el alfabeto más viejo de las te

**Técnica:** [CONFIANZA MEDIA] frag_* ts-ordenados, hex->morse -> 'SENAL DISPERSA'. Formato exacto sin verificar.

**Flag:** `NHK{[REDACTED]}`

### [199] El punto de encuentro — 450 pts

> Expediente final: posts de un operador nuevo y una foto sin texto encontrada en el mismo dispositivo. Combina ambas técnicas de los retos anteriores (lectura de acróstico + geoloca

**Técnica:** NHK{[REDACTED]} — Acrostico R-A-M-A + GPS -12.0477,-77.0344 -> Plaza San Martin.

**Flag:** `NHK{[REDACTED]}`

---

## Web  (9)

### [170] Boletín de la Hidra — 50 pts

> La Hidra publica un boletín para sus simpatizantes. Jura que no esconde nada, que todo está a la vista. Pero una bandera partida en tres cabezas no se ve de un vistazo: quien mira 

**Técnica:** Flag en 3 partes: comentario HTML + comentario CSS + /archivo-privado/.

**Flag:** `NHK{[REDACTED]}`

### [171] Sala de operadores — 75 pts

> La Hidra reparte carnés de colores a quienes entran a su sala. El portero no pide documentos: se fía de lo que llevas en el bolsillo. Si el carné dice «lector», solo ves el vestíbu

**Técnica:** Cookie rol=base64('lector') -> base64('admin').

**Flag:** `NHK{[REDACTED]}`

### [172] Repositorio olvidado — 100 pts

> Un desarrollador de la Hidra subió el portal de proveedores y se dejó la cartera encima del escritorio. Borró la clave a última hora, pero la memoria de un repositorio no olvida: c

**Técnica:** .git expuesto; blob de secrets.txt borrado (git rev-list --all).

**Flag:** `NHK{[REDACTED]}`

### [173] Acceso de operador — 100 pts

> El formulario de acceso de la Hidra responde con quejas muy detalladas cuando algo no le gusta. Quien sabe escucharlas aprende cómo está hecha la pregunta que le hacen a su base de

**Técnica:** SQLi login SQLite: bypass admin'-- ; UNION SELECT 1,clave,rol -> pass admin jmdj5BM5AdNX.

**Flag:** `NHK{[REDACTED]}`

### [174] Panel interno — 150 pts

> El portero del panel interno es riguroso… cuando le tocas la puerta con la mano abierta. Si llamas de otra forma, nadie vigila. Y la contraseña de un viejo conocido también abre es

**Técnica:** Auth solo en GET; POST /panel bypassa.

**Flag:** `NHK{[REDACTED]}`

### [175] Visor de informes — 200 pts

> La Hidra guarda sus informes en una carpeta y un visor los sirve de uno en uno. El visor es desconfiado: prohíbe subir de nivel borrando `../` de lo que le pides. Lo borra una vez,

**Técnica:** Path traversal: filtro quita ../ una vez -> ....//secreto/clave_w6.txt.

**Flag:** `NHK{[REDACTED]}`

### [176] Mesa de tickets — 200 pts

> La mesa de ayuda de la Hidra te presta una cuenta de práctica para ver tus propios tickets. Pero abre cualquier ticket a quien sepa su número, sin preguntar de quién es. En alguno,

**Técnica:** IDOR /api/tickets/<id> (login soporte/soporte2026); ticket 1028.

**Flag:** `NHK{[REDACTED]}`

### [177] Chatbot de la Hidra — 250 pts

> El chatbot de la Hidra solo habla en serio con administradores. A ti te trata de invitado y recuerda quién eres con una nota firmada que guarda en tu navegador. La firma depende de

**Técnica:** Flask session HS1 secret debil 'dragon'; forjar rol=admin -> /admin.

**Flag:** `NHK{[REDACTED]}`

### [178] Pasaporte de agente — 300 pts

> La Hidra emite pasaportes digitales (JWT) a sus agentes. Dice confiar en una firma que nadie puede falsificar sin la clave privada... y publica, por transparencia, la clave con la 

**Técnica:** JWT RS256->HS256 confusion: /clave_publica.pem como secreto HMAC; cookie pasaporte admin.

**Flag:** `NHK{[REDACTED]}`

---

## Linux  (6)

### [151] Bienvenido al cuartel — 30 pts

> **Nivel 0** · Conéctate y busca la bandera.

**Técnica:** SSH nivel0/capucha (truco SSH_ASKPASS+setsid). Flag en ~/leeme.txt.

**Flag:** `NHK{[REDACTED]}`

### [152] El guion misterioso — 40 pts

> Nivel 1 · Archivo cuyo nombre empieza con '-' (lo confunden con una opción).

**Técnica:** Archivo llamado '-'; leerlo con `cat ./-` o `cat -- -`.

**Flag:** `NHK{[REDACTED]}`

### [153] Palabras con espacios — 40 pts

> Nivel 2 · Nombre de archivo largo con espacios.

**Técnica:** Archivo 'el informe final.txt'; leer con comillas: `cat ./'el informe final.txt'` (grep -r también).

**Flag:** `NHK{[REDACTED]}`

### [154] Lo que no se ve — 40 pts

> Nivel 3 · Archivo oculto en archivos/.

**Técnica:** Dotfile archivos/.escondido; `ls -la` + cat, o `grep -r`.

**Flag:** `NHK{[REDACTED]}`

### [155] La única carta legible — 40 pts

> Nivel 4 · 10 archivos (nombre con '-'), solo 1 legible; el resto ruido con flags señuelo.

**Técnica:** Entre 10 '-archivoNN', identificar el ASCII legible (`file`/contenido): -archivo03. Los otros 9 son binario con flags decoy.

**Flag:** `NHK{[REDACTED]}`

### [156] Una aguja de 1033 bytes — 40 pts

> Nivel 5 · Archivo de exactamente 1033 bytes, legible y no ejecutable, entre cientos de cajas.

**Técnica:** `find ~/bodega -type f -size 1033c ! -executable` + filtrar los de texto → informe_final.txt.

**Flag:** `NHK{[REDACTED]}`

---

