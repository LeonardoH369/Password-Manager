# vault.py - persistencia con sqlite
# tabla meta = salt + verificador de la master password (nunca la password)
# tabla entries = cada campo cifrado por separado (title, user, pass, url, notes)
# asi hasta el titulo queda cifrado, si alguien roba el .db no ve ni para
# que servicio son las credenciales

import sqlite3
import time
import crypto_utils as cu


class Vault:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.execute("PRAGMA foreign_keys = ON")
        self._init_schema()

    def _init_schema(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS meta (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                salt BLOB NOT NULL,
                verifier TEXT NOT NULL,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until REAL NOT NULL DEFAULT 0
            )
        """)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title_enc TEXT NOT NULL,
                username_enc TEXT NOT NULL,
                password_enc TEXT NOT NULL,
                url_enc TEXT,
                notes_enc TEXT,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            )
        """)
        self.conn.commit()

    # ---------- Setup / autenticación ----------

    def is_initialized(self) -> bool:
        cur = self.conn.execute("SELECT 1 FROM meta WHERE id = 1")
        return cur.fetchone() is not None

    def setup_master_password(self, master_password: str) -> bytes:
        """Primer arranque: crea salt, deriva clave, guarda verificador."""
        salt = cu.generate_salt()
        key = cu.derive_key(master_password, salt)
        verifier = cu.make_master_verifier(key, salt)
        self.conn.execute(
            "INSERT INTO meta (id, salt, verifier, failed_attempts, locked_until) VALUES (1, ?, ?, 0, 0)",
            (salt, verifier),
        )
        self.conn.commit()
        return key

    def get_lockout_state(self):
        cur = self.conn.execute("SELECT failed_attempts, locked_until FROM meta WHERE id = 1")
        row = cur.fetchone()
        return row if row else (0, 0)

    def register_failed_attempt(self, max_attempts=5, lockout_seconds=30):
        """Rate limiting: tras max_attempts fallos, bloquea por lockout_seconds."""
        attempts, _ = self.get_lockout_state()
        attempts += 1
        locked_until = 0
        if attempts >= max_attempts:
            locked_until = time.time() + lockout_seconds
            attempts = 0  # reset counter tras aplicar el bloqueo
        self.conn.execute(
            "UPDATE meta SET failed_attempts = ?, locked_until = ? WHERE id = 1",
            (attempts, locked_until),
        )
        self.conn.commit()
        return locked_until

    def reset_failed_attempts(self):
        self.conn.execute("UPDATE meta SET failed_attempts = 0, locked_until = 0 WHERE id = 1")
        self.conn.commit()

    def try_login(self, master_password: str):
        """
        Devuelve (key, None) si el login es correcto,
        o (None, mensaje_error) si falla o está bloqueado.
        """
        attempts, locked_until = self.get_lockout_state()
        now = time.time()
        if locked_until and now < locked_until:
            remaining = int(locked_until - now)
            return None, f"Bóveda bloqueada. Intenta de nuevo en {remaining}s."

        cur = self.conn.execute("SELECT salt, verifier FROM meta WHERE id = 1")
        salt, verifier = cur.fetchone()
        key = cu.derive_key(master_password, salt)

        if cu.verify_master_password(key, verifier):
            self.reset_failed_attempts()
            return key, None
        else:
            self.register_failed_attempt()
            return None, "Contraseña maestra incorrecta."

    # ---------- CRUD de entradas ----------

    def add_entry(self, key: bytes, title: str, username: str, password: str,
                  url: str = "", notes: str = ""):
        now = time.time()
        self.conn.execute(
            """INSERT INTO entries
               (title_enc, username_enc, password_enc, url_enc, notes_enc, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                cu.encrypt(title, key),
                cu.encrypt(username, key),
                cu.encrypt(password, key),
                cu.encrypt(url, key) if url else "",
                cu.encrypt(notes, key) if notes else "",
                now, now,
            ),
        )
        self.conn.commit()

    def update_entry(self, key: bytes, entry_id: int, title: str, username: str,
                      password: str, url: str = "", notes: str = ""):
        self.conn.execute(
            """UPDATE entries SET title_enc=?, username_enc=?, password_enc=?,
               url_enc=?, notes_enc=?, updated_at=? WHERE id=?""",
            (
                cu.encrypt(title, key),
                cu.encrypt(username, key),
                cu.encrypt(password, key),
                cu.encrypt(url, key) if url else "",
                cu.encrypt(notes, key) if notes else "",
                time.time(), entry_id,
            ),
        )
        self.conn.commit()

    def delete_entry(self, entry_id: int):
        self.conn.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
        self.conn.commit()

    def get_all_entries(self, key: bytes):
        """Devuelve todas las entradas ya descifradas (solo en memoria)."""
        cur = self.conn.execute(
            "SELECT id, title_enc, username_enc, password_enc, url_enc, notes_enc FROM entries ORDER BY id"
        )
        results = []
        for row in cur.fetchall():
            entry_id, title_enc, user_enc, pass_enc, url_enc, notes_enc = row
            results.append({
                "id": entry_id,
                "title": cu.decrypt(title_enc, key),
                "username": cu.decrypt(user_enc, key),
                "password": cu.decrypt(pass_enc, key),
                "url": cu.decrypt(url_enc, key) if url_enc else "",
                "notes": cu.decrypt(notes_enc, key) if notes_enc else "",
            })
        return results

    def close(self):
        self.conn.close()
