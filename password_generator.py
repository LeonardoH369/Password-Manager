# password_generator.py
# uso secrets, no random - random usa Mersenne Twister que es predecible,
# secrets usa el CSPRNG del SO

import secrets
import string
import math


AMBIGUOUS_CHARS = "Il1O0"  # opcional excluir para legibilidad


def generate_password(length: int = 20, use_upper=True, use_lower=True,
                       use_digits=True, use_symbols=True,
                       exclude_ambiguous=False) -> str:
    if length < 8:
        raise ValueError("La longitud mínima recomendada es 8 caracteres.")

    pool = ""
    required_chars = []

    if use_lower:
        chars = string.ascii_lowercase
        pool += chars
        required_chars.append(secrets.choice(chars))
    if use_upper:
        chars = string.ascii_uppercase
        pool += chars
        required_chars.append(secrets.choice(chars))
    if use_digits:
        chars = string.digits
        pool += chars
        required_chars.append(secrets.choice(chars))
    if use_symbols:
        chars = "!@#$%^&*()-_=+[]{};:,.<>?"
        pool += chars
        required_chars.append(secrets.choice(chars))

    if not pool:
        raise ValueError("Debes habilitar al menos un tipo de carácter.")

    if exclude_ambiguous:
        pool = "".join(c for c in pool if c not in AMBIGUOUS_CHARS)

    # Genera el resto de la contraseña de forma aleatoria segura
    remaining_length = length - len(required_chars)
    rest = [secrets.choice(pool) for _ in range(remaining_length)]

    all_chars = required_chars + rest
    # fisher-yates a mano porque secrets no trae shuffle propio
    for i in range(len(all_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        all_chars[i], all_chars[j] = all_chars[j], all_chars[i]

    return "".join(all_chars)


def estimate_entropy_bits(password: str) -> float:
    # entropy = length * log2(pool_size), asumiendo que el atacante ya
    # sabe que charset usaste (peor caso)
    pool_size = 0
    if any(c.islower() for c in password):
        pool_size += 26
    if any(c.isupper() for c in password):
        pool_size += 26
    if any(c.isdigit() for c in password):
        pool_size += 10
    if any(not c.isalnum() for c in password):
        pool_size += 32

    if pool_size == 0:
        return 0.0
    return len(password) * math.log2(pool_size)


def strength_label(bits: float) -> str:
    if bits < 40:
        return "Muy débil"
    elif bits < 60:
        return "Débil"
    elif bits < 80:
        return "Aceptable"
    elif bits < 100:
        return "Fuerte"
    else:
        return "Muy fuerte"
