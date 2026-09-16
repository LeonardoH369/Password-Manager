# Password Manager

Desktop password manager built in Python. I started it as a cybersecurity
portfolio project, but ended up actually using it for my own accounts — no
more excuses for reusing passwords across sites.

Everything is encrypted and stays local on your machine, nothing gets
uploaded anywhere (except when checking if a password has already been
leaked, and even then you don't send the full password — more on that
below).

## What it does

- Stores username/password/notes for each account, all encrypted with
  AES-256-GCM
- The master password is never stored anywhere — it only lives in RAM
  while the app is open
- Auto-locks after a few minutes of inactivity
- Generates truly random passwords (using `secrets`, not `random`)
- Warns you if a password has already shown up in a known breach (using
  the Have I Been Pwned API)
- Clipboard auto-clear after 20s, so a copied password doesn't stay
  sitting there if you get distracted

## How it's built under the hood

The master password goes through Argon2id (winner of the 2015 Password
Hashing Competition) to derive a 256-bit key. I chose Argon2id over
something like PBKDF2 because it's *memory-hard* — brute-forcing your
password requires spending a lot of RAM per attempt, not just CPU, which
takes away a lot of the advantage from GPU-based attacks.

With that key, I encrypt each field of each entry separately using
AES-256-GCM. It's an authenticated encryption mode, meaning that if
someone tampers with even a single byte of the encrypted file, decryption
simply fails instead of silently returning garbage — so you know right
away if something got corrupted or manipulated.

For the breach checking, I use something called k-anonymity: instead of
sending your password (or its full hash) to the HIBP server, I only send
the first 5 characters of the SHA-1 hash. The server returns a list of
thousands of hashes that share that same prefix, and I compare the rest
locally. That way the server never learns exactly which password I'm
checking.

All of this lives in a local SQLite file — no server, no cloud, no sync
between devices (for now).

## Installation

```bash
git clone https://github.com/LeonardoH369/Password-Manager.git
cd Password-Manager
python -m venv venv
venv\Scripts\Activate.ps1      # on Windows
pip install -r requirements.txt
python main.py
```

The first time you run it, it'll ask you to create your master password.
Heads up: there's no way to recover it if you forget it — that's
intentional (that's how zero-knowledge works).

## Building the .exe

```powershell
pip install pyinstaller
python -m PyInstaller --noconfirm --onedir --windowed --name "PasswordManager" --collect-all customtkinter --hidden-import "tkinter.filedialog" --hidden-import "tkinter.messagebox" --hidden-import "tkinter.colorchooser" --hidden-import "platform" --hidden-import "darkdetect" --hidden-import "packaging" main.py
```

It ends up in `dist/PasswordManager/PasswordManager.exe`. It has to be
`--onedir` and not `--onefile`, because CustomTkinter needs its theme
files as a separate folder — otherwise it fails looking for them.

## Structure

```
password_manager/
├── main.py                # the GUI
├── crypto_utils.py        # Argon2id + AES-256-GCM
├── vault.py                # SQLite persistence + attempt lockout
├── password_generator.py  # password generator
├── breach_check.py        # HIBP check with k-anonymity
├── security.py             # auto-lock + clipboard cleanup
├── requirements.txt
├── README.md
└── THREAT_MODEL.md        # deeper threat analysis (STRIDE)
```

## Known limitations (being honest)

- Python doesn't 100% guarantee wiping the key from RAM due to garbage
  collection — for something more serious you'd need to get into locked
  memory (`mlock`) or a different language with manual memory control
- It doesn't protect you if someone has root/admin access on your machine
  while the app is unlocked — no software password manager does, that's
  what HSMs are for
- It doesn't sync between devices, it's 100% local on purpose

More detail on this, and on what other threats I considered, is in
[`THREAT_MODEL.md`](THREAT_MODEL.md).

## What I'm planning to add

- Local 2FA (TOTP) before unlocking the vault
- Encrypted export/import for backups
- Warn if the same password was reused across multiple entries
- A proper installer instead of a loose folder

---

Made by [Leonardo Hinojosa](https://github.com/LeonardoH369) — Software
Development Engineering student, focused on networking and cybersecurity.
