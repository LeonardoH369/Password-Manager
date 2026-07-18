# Password Manager

Gestor de contraseñas de escritorio hecho en Python. Lo empecé como proyecto
de portafolio para ciberseguridad, pero terminé usándolo de verdad para mis
propias cuentas — ya no tengo pretexto para reusar contraseñas entre sitios.

Todo se cifra y se queda local en tu máquina, nada se sube a ningún lado
(excepto cuando checas si una contraseña ya fue filtrada, y ahí ni siquiera
mandas la contraseña completa — más abajo explico cómo).

## Qué hace

- Guarda usuario/contraseña/notas de cada cuenta, todo cifrado con AES-256-GCM
- La contraseña maestra nunca se guarda en ningún lado — solo vive en RAM
  mientras tienes la app abierta
- Se bloquea sola si te quedas inactivo unos minutos
- Genera contraseñas random de verdad (usando `secrets`, no `random`)
- Te avisa si una contraseña ya apareció en alguna filtración conocida
  (usando la API de Have I Been Pwned)
- Copia con auto-borrado del portapapeles a los 20s, para que no se quede
  ahí pegada si te distraes

## Cómo está armado por dentro

La contraseña maestra pasa por Argon2id (el ganador de la Password Hashing
Competition del 2015) para sacar una llave de 256 bits. Elegí Argon2id
en vez de algo como PBKDF2 porque es *memory-hard* — para que alguien intente
adivinar tu contraseña por fuerza bruta necesita gastar mucha RAM por
intento, no solo CPU, lo cual le quita bastante la ventaja a quien intente
tirar el ataque con GPUs.

Con esa llave cifro cada campo de cada entrada por separado usando
AES-256-GCM. Es un modo de cifrado autenticado, o sea que si alguien le
mueve un solo byte al archivo cifrado, al intentar descifrarlo simplemente
truena en vez de regresar basura silenciosamente — así te enteras si algo
se corrompió o fue manipulado.

Para lo de las filtraciones, uso algo que se llama k-anonymity: en vez de
mandar tu contraseña (o su hash completo) al servidor de HIBP, solo mando
los primeros 5 caracteres del hash SHA-1. El servidor me regresa una lista
de miles de hashes que comparten ese mismo prefijo, y yo comparo el resto
localmente. Así el servidor nunca sabe qué contraseña exacta estoy
consultando.

Todo esto vive en un archivo SQLite local — no hay servidor, no hay nube,
no hay sync entre dispositivos (por ahora).

## Instalación

```bash
git clone https://github.com/LeonardoH369/Password-Manager.git
cd Password-Manager
python -m venv venv
venv\Scripts\Activate.ps1      # en Windows
pip install -r requirements.txt
python main.py
```

La primera vez te va a pedir crear tu contraseña maestra. Ojo: no hay forma
de recuperarla si se te olvida, es intencional (así funciona zero-knowledge).

## Generar el .exe

```powershell
pip install pyinstaller
python -m PyInstaller --noconfirm --onedir --windowed --name "PasswordManager" --collect-all customtkinter --hidden-import "tkinter.filedialog" --hidden-import "tkinter.messagebox" --hidden-import "tkinter.colorchooser" --hidden-import "platform" --hidden-import "darkdetect" --hidden-import "packaging" main.py
```

Queda en `dist/PasswordManager/PasswordManager.exe`. Tiene que ser
`--onedir` y no `--onefile` porque CustomTkinter necesita sus archivos de
tema como carpeta aparte, si no truena buscándolos.

## Estructura

```
password_manager/
├── main.py                # la GUI
├── crypto_utils.py        # Argon2id + AES-256-GCM
├── vault.py                # persistencia en SQLite + lockout de intentos
├── password_generator.py  # generador de contraseñas
├── breach_check.py        # check contra HIBP con k-anonymity
├── security.py             # auto-lock + limpieza de clipboard
├── requirements.txt
├── README.md
└── THREAT_MODEL.md        # análisis de amenazas más a fondo (STRIDE)
```

## Cosas que le faltan (siendo honesto)

- Python no garantiza borrar la clave de la RAM al 100% por el garbage
  collector — para algo más serio habría que meterse a memoria bloqueada
  (`mlock`) o directamente otro lenguaje con control manual de memoria
- No te protege si alguien tiene acceso root/admin en tu máquina mientras
  la app está desbloqueada — ningún password manager de software lo hace,
  para eso existen los HSM
- No sincroniza entre dispositivos, es 100% local a propósito

Más detalle de esto y de qué otras amenazas consideré está en
[`THREAT_MODEL.md`](THREAT_MODEL.md).

## Qué le voy a ir agregando

- 2FA local (TOTP) antes de desbloquear la bóveda
- Export/import cifrado para poder respaldar
- Avisar si reusaste la misma contraseña en varias entradas
- Instalador en vez de carpeta suelta

---

Hecho por [Leonardo Hinojosa](https://github.com/LeonardoH369) — estudiante
de Ing. en Desarrollo de Software, enfocado en redes y ciberseguridad.
