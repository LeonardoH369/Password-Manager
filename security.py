# security.py
# auto-lock por inactividad + auto-clear del clipboard.
# nota: python no garantiza zeroizar la key en memoria al 100% por el
# garbage collector, es una limitación conocida (no hay mucho que hacer
# sin meterse a librerías de memoria bloqueada tipo mlock)

import threading
import time
import pyperclip


class ClipboardManager:
    def __init__(self, clear_after_seconds: int = 20):
        self.clear_after_seconds = clear_after_seconds
        self._timer = None
        self._last_copied_value = None

    def copy_with_autoclear(self, value: str):
        """Copia un valor al portapapeles y programa su limpieza automática."""
        if self._timer:
            self._timer.cancel()

        pyperclip.copy(value)
        self._last_copied_value = value

        self._timer = threading.Timer(self.clear_after_seconds, self._clear)
        self._timer.daemon = True
        self._timer.start()

    def _clear(self):
        # Solo borra si el clipboard sigue teniendo lo que nosotros pusimos
        # (evita borrar algo que el usuario copió manualmente después)
        try:
            if pyperclip.paste() == self._last_copied_value:
                pyperclip.copy("")
        except Exception:
            pass


class SessionManager:
    # auto-lock por inactividad. la GUI llama touch() en cada click/tecla
    def __init__(self, timeout_seconds: int = 120, on_lock=None):
        self.timeout_seconds = timeout_seconds
        self.on_lock = on_lock
        self.last_activity = time.time()
        self._running = True
        self._thread = threading.Thread(target=self._watch, daemon=True)
        self._thread.start()

    def touch(self):
        self.last_activity = time.time()

    def _watch(self):
        while self._running:
            time.sleep(1)
            if time.time() - self.last_activity > self.timeout_seconds:
                if self.on_lock:
                    self.on_lock()
                self.last_activity = time.time()  # evita repetidos

    def stop(self):
        self._running = False
