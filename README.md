# 🔐 Password Manager

Gestor de contraseñas de escritorio, cifrado localmente, construido en Python
con foco en buenas prácticas de seguridad aplicada (no solo "que funcione",
sino que funcione de forma defendible ante una auditoría básica).

## Características

- Cifrado **AES-256-GCM** (autenticado) para cada campo sensible de cada entrada
- Derivación de clave con **Argon2id** (memory-hard, resistente a GPU/ASIC)
- Arquitectura **zero-knowledge**: la contraseña maestra y la clave derivada
  nunca tocan el disco
- **Rate limiting / lockout** tras intentos fallidos de login
- **Auto-lock** por inactividad (bloquea la sesión y descarta la clave de memoria)
- **Auto-limpieza del portapapeles** tras copiar una contraseña
- **Generador de contraseñas** con CSPRNG (`secrets`, no `random`) + estimación de entropía
- **Verificación de contraseñas filtradas** contra la API de Have I Been Pwned
  usando **k-anonymity** (nunca se envía la contraseña completa a un tercero)

## Arquitectura de seguridad

```
Contraseña maestra (nunca se guarda)
        │
        ▼
   Argon2id KDF  ──uses──▶  salt aleatorio (guardado en DB)
        │
        ▼
  Clave de 256 bits (solo en RAM durante la sesión)
        │
        ▼
  AES-256-GCM  ──▶ cifra cada campo de cada entrada individualmente
        │            (nonce único de 12 bytes por campo)
        ▼
  SQLite (.db)  ──▶ solo contiene: salt, verificador, y blobs cifrados
```

### ¿Por qué Argon2id y no bcrypt/PBKDF2?

Argon2id ganó la Password Hashing Competition (2015) y es la recomendación
actual de OWASP para KDFs de contraseñas. A diferencia de PBKDF2 (solo
CPU-hard), Argon2 es *memory-hard*: obliga a un atacante a usar cantidades
grandes de RAM por intento, lo que anula la ventaja de paralelismo masivo
que dan las GPUs/ASICs en ataques de fuerza bruta offline.

### ¿Por qué AES-GCM y no AES-CBC?

GCM es un modo de cifrado *autenticado* (AEAD): además de confidencialidad,
provee integridad. Si un atacante modifica un solo bit del ciphertext
guardado en disco, la desencriptación falla explícitamente (`InvalidTag`)
en vez de devolver datos corruptos silenciosamente, que es lo que pasaría
con CBC sin un MAC adicional.

### ¿Qué es k-anonymity y por qué importa aquí?

Al verificar si una contraseña fue filtrada, nunca mandamos la contraseña
(ni su hash completo) a un servidor externo. Solo mandamos los primeros
5 caracteres del hash SHA-1. El servidor responde con *todos* los hashes
que comparten ese prefijo (miles de candidatos), y la comparación final
se hace localmente. El servidor jamás sabe qué contraseña exacta estás
consultando — es privacidad por diseño, no por promesa.

## Instalación

```bash
pip install -r requirements.txt
python3 main.py
```

## Limitaciones conocidas (documentadas honestamente, como se haría en un
modelo de amenazas real)

- Python no garantiza zeroización de memoria (el garbage collector puede
  dejar copias de la clave en RAM más tiempo del ideal). Para un producto
  real de nivel empresarial, esto se mitigaría con librerías de memoria
  bloqueada (`mlock`) o reescribiendo el núcleo criptográfico en un
  lenguaje con control manual de memoria.
- No protege contra un atacante con acceso root/administrator mientras
  la app está desbloqueada (ningún password manager de software puro lo
  hace — para eso existen HSMs / Secure Enclave).
- No hay sincronización multi-dispositivo (por diseño: todo es local,
  lo cual reduce superficie de ataque pero también conveniencia).

## Estructura del proyecto

```
password_manager/
├── main.py                # GUI (CustomTkinter)
├── crypto_utils.py        # KDF Argon2id + AES-256-GCM
├── vault.py                # Persistencia SQLite + lockout
├── password_generator.py  # Generador CSPRNG + entropía
├── breach_check.py        # HIBP con k-anonymity
├── security.py             # Auto-lock + clipboard autoclear
├── requirements.txt
├── README.md
└── THREAT_MODEL.md
```
