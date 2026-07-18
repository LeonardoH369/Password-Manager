# main.py - GUI del password manager
# pantalla de login/setup -> boveda principal con lista de entradas,
# generador de passwords, check de filtraciones, autolock, etc.

import os
import customtkinter as ctk
from tkinter import messagebox

from vault import Vault
from password_generator import generate_password, estimate_entropy_bits, strength_label
from breach_check import check_password_pwned
from security import SessionManager, ClipboardManager

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")


ACCENT = "#22C55E"
ACCENT_HOVER = "#16A34A"
DANGER = "#B91C1C"
DANGER_HOVER = "#991B1B"
NEUTRAL = "#3F3F46"
NEUTRAL_HOVER = "#52525B"

DB_PATH = os.path.join(os.path.expanduser("~"), ".pw_manager_vault.db")
AUTOLOCK_SECONDS = 120
CLIPBOARD_CLEAR_SECONDS = 20


class PasswordManagerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Password Manager")
        self.geometry("900x600")
        self.minsize(760, 480)

        self.vault = Vault(DB_PATH)
        self.session_key = None  # clave derivada, solo en memoria mientras hay sesión
        self.clipboard_mgr = ClipboardManager(clear_after_seconds=CLIPBOARD_CLEAR_SECONDS)
        self.session_mgr = None

        # Registrar actividad del usuario para el auto-lock
        self.bind_all("<Any-KeyPress>", self._on_activity)
        self.bind_all("<Any-Button>", self._on_activity)

        self._build_auth_screen()

    def _on_activity(self, event=None):
        if self.session_mgr:
            self.session_mgr.touch()

    # ---------------- Pantalla de autenticación ----------------

    def _build_auth_screen(self):
        self._clear_window()
        frame = ctk.CTkFrame(self)
        frame.pack(expand=True)

        is_new = not self.vault.is_initialized()
        title_text = "Crear contraseña maestra" if is_new else "Desbloquear bóveda"
        ctk.CTkLabel(frame, text="🔐 Password Manager", font=("Arial", 26, "bold")).pack(pady=(30, 5))
        ctk.CTkLabel(frame, text=title_text, font=("Arial", 15)).pack(pady=(0, 20))

        pw_entry = ctk.CTkEntry(frame, placeholder_text="Contraseña maestra", show="•", width=280)
        pw_entry.pack(pady=6)
        pw_entry.focus()

        confirm_entry = None
        if is_new:
            confirm_entry = ctk.CTkEntry(frame, placeholder_text="Confirmar contraseña", show="•", width=280)
            confirm_entry.pack(pady=6)
            ctk.CTkLabel(
                frame, text="Mínimo 12 caracteres. Esta contraseña NO se puede\nrecuperar si la olvidas — no se guarda en ningún lado.",
                font=("Arial", 11), text_color="gray"
            ).pack(pady=(4, 0))

        error_label = ctk.CTkLabel(frame, text="", text_color="#ff6666")
        error_label.pack(pady=(8, 0))

        def submit():
            pw = pw_entry.get()
            if is_new:
                confirm = confirm_entry.get()
                if len(pw) < 12:
                    error_label.configure(text="La contraseña debe tener al menos 12 caracteres.")
                    return
                if pw != confirm:
                    error_label.configure(text="Las contraseñas no coinciden.")
                    return
                self.session_key = self.vault.setup_master_password(pw)
                self._start_session()
            else:
                key, err = self.vault.try_login(pw)
                if err:
                    error_label.configure(text=err)
                    pw_entry.delete(0, "end")
                    return
                self.session_key = key
                self._start_session()

        btn_text = "Crear bóveda" if is_new else "Desbloquear"
        ctk.CTkButton(frame, text=btn_text, width=280, fg_color=ACCENT, hover_color=ACCENT_HOVER,
                      command=submit).pack(pady=16)
        pw_entry.bind("<Return>", lambda e: submit())
        if confirm_entry:
            confirm_entry.bind("<Return>", lambda e: submit())

    def _start_session(self):
        self.session_mgr = SessionManager(timeout_seconds=AUTOLOCK_SECONDS, on_lock=self._lock_vault)
        self._build_vault_screen()

    def _lock_vault(self):
        # Se ejecuta desde el hilo del SessionManager -> hay que saltar al hilo de la GUI
        def do_lock():
            self.session_key = None
            messagebox.showinfo("Bloqueado", "La bóveda se bloqueó por inactividad.")
            self._build_auth_screen()
        self.after(0, do_lock)

    # ---------------- Pantalla principal de la bóveda ----------------

    def _build_vault_screen(self):
        self._clear_window()

        top_bar = ctk.CTkFrame(self)
        top_bar.pack(fill="x", padx=16, pady=(16, 8))

        self.search_var = ctk.StringVar()
        search_entry = ctk.CTkEntry(top_bar, placeholder_text="🔍 Buscar...", textvariable=self.search_var, width=300)
        search_entry.pack(side="left")
        self.search_var.trace_add("write", lambda *a: self._refresh_entry_list())

        ctk.CTkButton(top_bar, text="+ Nueva entrada", fg_color=ACCENT, hover_color=ACCENT_HOVER,
                      command=self._open_entry_dialog).pack(side="right", padx=(6, 0))
        ctk.CTkButton(top_bar, text="🔒 Bloquear ahora", fg_color=NEUTRAL, hover_color=NEUTRAL_HOVER,
                      command=lambda: self._lock_vault()).pack(side="right", padx=(6, 0))

        self.list_frame = ctk.CTkScrollableFrame(self)
        self.list_frame.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        self._refresh_entry_list()

    def _refresh_entry_list(self):
        for widget in self.list_frame.winfo_children():
            widget.destroy()

        entries = self.vault.get_all_entries(self.session_key)
        query = self.search_var.get().lower().strip() if hasattr(self, "search_var") else ""
        if query:
            entries = [e for e in entries if query in e["title"].lower() or query in e["username"].lower()]

        if not entries:
            ctk.CTkLabel(self.list_frame, text="No hay entradas todavía.", text_color="gray").pack(pady=30)
            return

        for entry in entries:
            self._build_entry_row(entry)

    def _build_entry_row(self, entry):
        row = ctk.CTkFrame(self.list_frame)
        row.pack(fill="x", pady=4, padx=2)

        info = ctk.CTkFrame(row, fg_color="transparent")
        info.pack(side="left", fill="x", expand=True, padx=10, pady=8)
        ctk.CTkLabel(info, text=entry["title"], font=("Arial", 14, "bold"), anchor="w").pack(fill="x")
        ctk.CTkLabel(info, text=entry["username"], font=("Arial", 12), text_color="gray", anchor="w").pack(fill="x")

        btns = ctk.CTkFrame(row, fg_color="transparent")
        btns.pack(side="right", padx=8)

        ctk.CTkButton(btns, text="Copiar user", width=90, fg_color=NEUTRAL, hover_color=NEUTRAL_HOVER,
                      command=lambda e=entry: self._copy_value(e["username"], "Usuario")).pack(side="left", padx=3)
        ctk.CTkButton(btns, text="Copiar pass", width=90, fg_color=ACCENT, hover_color=ACCENT_HOVER,
                      command=lambda e=entry: self._copy_value(e["password"], "Contraseña")).pack(side="left", padx=3)
        ctk.CTkButton(btns, text="Editar", width=70, fg_color=NEUTRAL, hover_color=NEUTRAL_HOVER,
                      command=lambda e=entry: self._open_entry_dialog(e)).pack(side="left", padx=3)
        ctk.CTkButton(btns, text="Eliminar", width=70, fg_color=DANGER, hover_color=DANGER_HOVER,
                      command=lambda e=entry: self._delete_entry(e)).pack(side="left", padx=3)

    def _copy_value(self, value, label):
        self.clipboard_mgr.copy_with_autoclear(value)
        messagebox.showinfo("Copiado", f"{label} copiado. Se borrará del portapapeles en {CLIPBOARD_CLEAR_SECONDS}s.")

    def _delete_entry(self, entry):
        if messagebox.askyesno("Confirmar", f"¿Eliminar '{entry['title']}'?"):
            self.vault.delete_entry(entry["id"])
            self._refresh_entry_list()

    # ---------------- Diálogo de agregar/editar entrada ----------------

    def _open_entry_dialog(self, entry=None):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Editar entrada" if entry else "Nueva entrada")
        dialog.geometry("420x480")
        dialog.transient(self)
        dialog.grab_set()

        fields = {}
        for key_name, label in [("title", "Título"), ("username", "Usuario / email"),
                                 ("url", "URL"), ("notes", "Notas")]:
            ctk.CTkLabel(dialog, text=label, anchor="w").pack(fill="x", padx=20, pady=(10, 0))
            entry_widget = ctk.CTkEntry(dialog, width=360)
            entry_widget.pack(padx=20)
            if entry:
                entry_widget.insert(0, entry.get(key_name, ""))
            fields[key_name] = entry_widget

        ctk.CTkLabel(dialog, text="Contraseña", anchor="w").pack(fill="x", padx=20, pady=(10, 0))
        pw_row = ctk.CTkFrame(dialog, fg_color="transparent")
        pw_row.pack(padx=20, fill="x")
        pw_entry = ctk.CTkEntry(pw_row, width=270, show="•")
        pw_entry.pack(side="left")
        if entry:
            pw_entry.insert(0, entry.get("password", ""))

        def toggle_show():
            pw_entry.configure(show="" if pw_entry.cget("show") == "•" else "•")
        ctk.CTkButton(pw_row, text="👁", width=30, command=toggle_show).pack(side="left", padx=(6, 0))

        strength_label_widget = ctk.CTkLabel(dialog, text="", font=("Arial", 11))
        strength_label_widget.pack(pady=(4, 0))

        def update_strength(*a):
            pw = pw_entry.get()
            if pw:
                bits = estimate_entropy_bits(pw)
                strength_label_widget.configure(text=f"Entropía: {bits:.0f} bits — {strength_label(bits)}")
            else:
                strength_label_widget.configure(text="")
        pw_entry.bind("<KeyRelease>", update_strength)
        update_strength()

        def generate_and_fill():
            pw = generate_password(length=20)
            pw_entry.delete(0, "end")
            pw_entry.insert(0, pw)
            update_strength()

        def check_breach():
            pw = pw_entry.get()
            if not pw:
                return
            is_pwned, count = check_password_pwned(pw)
            if is_pwned is None:
                messagebox.showwarning("Sin conexión", "No se pudo verificar (revisa tu conexión a internet).")
            elif is_pwned:
                messagebox.showerror(
                    "Contraseña filtrada",
                    f"Esta contraseña apareció en {count:,} filtraciones de datos conocidas.\n¡Cámbiala!"
                )
            else:
                messagebox.showinfo("Todo bien", "Esta contraseña no aparece en filtraciones conocidas.")

        action_row = ctk.CTkFrame(dialog, fg_color="transparent")
        action_row.pack(pady=10)
        ctk.CTkButton(action_row, text="Generar", command=generate_and_fill, width=110,
                      fg_color=NEUTRAL, hover_color=NEUTRAL_HOVER).pack(side="left", padx=4)
        ctk.CTkButton(action_row, text="Verificar filtración", command=check_breach, width=140,
                      fg_color=NEUTRAL, hover_color=NEUTRAL_HOVER).pack(side="left", padx=4)

        def save():
            title = fields["title"].get().strip()
            username = fields["username"].get().strip()
            password = pw_entry.get()
            url = fields["url"].get().strip()
            notes = fields["notes"].get().strip()

            if not title or not password:
                messagebox.showwarning("Faltan datos", "Título y contraseña son obligatorios.")
                return

            if entry:
                self.vault.update_entry(self.session_key, entry["id"], title, username, password, url, notes)
            else:
                self.vault.add_entry(self.session_key, title, username, password, url, notes)

            dialog.destroy()
            self._refresh_entry_list()

        ctk.CTkButton(dialog, text="Guardar", command=save, width=200,
                      fg_color=ACCENT, hover_color=ACCENT_HOVER).pack(pady=(10, 20))

    def _clear_window(self):
        for widget in self.winfo_children():
            widget.destroy()

    def on_closing(self):
        if self.session_mgr:
            self.session_mgr.stop()
        self.vault.close()
        self.destroy()


if __name__ == "__main__":
    app = PasswordManagerApp()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()
