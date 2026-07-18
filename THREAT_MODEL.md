# Modelo de amenazas — Password Manager

Análisis informal usando la lógica de **STRIDE** (Spoofing, Tampering,
Repudiation, Information Disclosure, Denial of Service, Elevation of
Privilege), aplicado a los activos principales del sistema.

## Activos a proteger

1. La contraseña maestra
2. La clave de cifrado derivada (en memoria durante la sesión)
3. Las credenciales guardadas (usuario/contraseña/notas de cada entrada)
4. El archivo de base de datos (`.db`) en disco

## Actores de amenaza considerados

- **Atacante con acceso al archivo `.db`** (robo de laptop, backup filtrado, malware con acceso a archivos)
- **Atacante con acceso a la red** (mientras se consulta la API de HIBP)
- **Atacante con acceso físico momentáneo** a la sesión desbloqueada
- **Atacante que intenta fuerza bruta** contra la contraseña maestra

## Análisis por amenaza

| # | Amenaza (STRIDE) | Escenario | Mitigación implementada |
|---|---|---|---|
| 1 | Information Disclosure | Alguien roba el archivo `.db` | Todos los campos sensibles están cifrados con AES-256-GCM; sin la clave (derivada de la contraseña maestra vía Argon2id) el contenido es indistinguible de ruido aleatorio |
| 2 | Tampering | Alguien modifica el `.db` para inyectar datos falsos | El tag de autenticación de GCM detecta cualquier modificación del ciphertext; la desencriptación falla explícitamente |
| 3 | Spoofing / Brute force | Ataque de fuerza bruta offline contra la contraseña maestra | Argon2id (memory-hard, 64MB/intento) hace que probar millones de contraseñas sea computacional y económicamente costoso |
| 4 | Spoofing / Brute force | Ataque de fuerza bruta online (intentos repetidos en la app) | Lockout tras 5 intentos fallidos (30s de bloqueo, escalable) |
| 5 | Information Disclosure | Sesión desbloqueada y abandonada (ataque "shoulder surfing" o acceso físico momentáneo) | Auto-lock tras 120s de inactividad; la clave se descarta de la variable en memoria |
| 6 | Information Disclosure | Contraseña queda en el portapapeles indefinidamente | Auto-limpieza del clipboard 20s después de copiar |
| 7 | Information Disclosure | Verificar si una contraseña fue filtrada expone la contraseña a un tercero (HIBP) | k-anonymity: solo se envía un prefijo de 5 caracteres del hash SHA-1, nunca la contraseña ni el hash completo |
| 8 | Denial of Service | Verificación de filtraciones sin conexión bloquea el uso normal | La función retorna `(None, None)` en caso de fallo de red en vez de lanzar excepción que tumbe la app |
| 9 | Elevation of Privilege | Malware/atacante con el mismo usuario del SO mientras la app corre | **Fuera de alcance** — ningún password manager de software puro defiende contra un atacante con el mismo nivel de privilegios que el usuario en tiempo real; requeriría TPM/Secure Enclave |

## Amenazas explícitamente fuera de alcance (y por qué)

- **Keyloggers**: si el sistema operativo del usuario está comprometido con
  un keylogger, ninguna aplicación de escritorio puede proteger la
  contraseña maestra en el momento de tecleo. Mitigación real: seguridad
  del endpoint (antivirus, EDR), no responsabilidad de esta app.
- **Ataques de canal lateral (timing attacks) sobre Argon2id/AES**: se
  asume que las implementaciones de las librerías `argon2-cffi` y
  `cryptography` (basada en OpenSSL) ya están hardened contra esto —
  no se reimplementa criptografía desde cero, que es la primera regla
  de "no hagas tu propia criptografía".
- **Sincronización en la nube**: no implementada por diseño; reduce
  superficie de ataque a costa de conveniencia multi-dispositivo.

## Posibles mejoras futuras (para ir ampliando el proyecto)

- 2FA local (TOTP) como segundo factor antes de desbloquear la bóveda
- Export/import cifrado para backups portables
- Campo de "expiración" que sugiera rotar contraseñas viejas
- Auditoría de contraseñas reutilizadas entre entradas
- Empaquetado como ejecutable standalone (PyInstaller) para no depender de `pip install`
