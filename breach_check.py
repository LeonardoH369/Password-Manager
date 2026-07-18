# breach_check.py - checa contra la API de Have I Been Pwned si una
# password ya aparece en alguna filtración de datos conocida.
#
# k-anonymity: nunca mando la password completa ni el hash completo al
# servidor. Solo los primeros 5 chars del sha1 (el prefijo). HIBP regresa
# todos los hashes que comparten ese prefijo (miles) y yo comparo el resto
# localmente. Así el server nunca sabe que password exacta estoy chequeando.

import hashlib
import requests

HIBP_API_URL = "https://api.pwnedpasswords.com/range/"


def check_password_pwned(password: str, timeout: float = 5.0):
    # regresa (True/False, count) o (None, None) si no hay internet -
    # nunca debe tronar la app solo por no tener conexión
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        resp = requests.get(
            HIBP_API_URL + prefix,
            timeout=timeout,
            headers={"Add-Padding": "true"},  # mitiga ataques de análisis por tamaño de respuesta
        )
        resp.raise_for_status()
    except requests.RequestException:
        return None, None

    for line in resp.text.splitlines():
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
            return True, int(count)

    return False, 0
