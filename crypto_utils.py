# crypto_utils.py
# KDF con Argon2id (mem-hard, gana la PHC 2015, mejor que bcrypt/PBKDF2 contra GPU)
# + AES-256-GCM para cifrar cada campo (autenticado, si alguien toca el
# ciphertext la desencriptación truena en vez de dar basura silenciosa).
# La master password nunca se guarda, solo vive en RAM mientras hay sesión.

import os
import base64
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- Parámetros de Argon2id (ajustados para uso interactivo de escritorio) ---
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536  # 64 MB en KiB
ARGON2_PARALLELISM = 4
KEY_LENGTH = 32  # 256 bits para AES-256

SALT_LENGTH = 16
NONCE_LENGTH = 12  # tamaño estándar recomendado para GCM


def generate_salt() -> bytes:
    # os.urandom usa el CSPRNG del SO, no random normal
    return os.urandom(SALT_LENGTH)


def derive_key(master_password: str, salt: bytes) -> bytes:
    # deriva la key de 256 bits que se usa para cifrar/descifrar todo
    key = hash_secret_raw(
        secret=master_password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=KEY_LENGTH,
        type=Type.ID,  # Argon2id
    )
    return key


def encrypt(plaintext: str, key: bytes) -> str:
    # nonce nuevo cada vez, nunca se reusa. el tag va pegado al final
    # del ciphertext (asi lo maneja AESGCM internamente)
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_LENGTH)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), associated_data=None)
    blob = nonce + ciphertext  # el tag ya viene incluido al final de ciphertext
    return base64.b64encode(blob).decode("utf-8")


def decrypt(blob_b64: str, key: bytes) -> str:
    # si el blob fue modificado o la key esta mal, esto truena con InvalidTag
    blob = base64.b64decode(blob_b64)
    nonce = blob[:NONCE_LENGTH]
    ciphertext = blob[NONCE_LENGTH:]
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    return plaintext.decode("utf-8")


def make_master_verifier(key: bytes, salt: bytes) -> str:
    # truco para no guardar la password en ningun lado: ciframos un valor
    # conocido con la key derivada. si en el login logramos descifrarlo
    # bien, la key (y la password) son correctas
    return encrypt("VALID", key)


def verify_master_password(entered_key: bytes, verifier_blob: str) -> bool:
    # intenta descifrar el verificador, si falla la password esta mal
    try:
        result = decrypt(verifier_blob, entered_key)
        return result == "VALID"
    except Exception:
        return False
