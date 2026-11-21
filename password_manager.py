import json
import os
import base64
import getpass
import secrets
import string
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidTag

VAULT_PATH = "vault.enc"


def derive_key(master_password, salt):
    kdf = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1)
    return kdf.derive(master_password.encode())
def encrypt(entries, key):
    nonce = os.urandom(12)
    data = json.dumps(entries).encode()
    ciphertext = AESGCM(key).encrypt(nonce, data, None)
    return nonce, ciphertext


def decrypt(nonce, ciphertext, key):
    data = AESGCM(key).decrypt(nonce, ciphertext, None)
    return json.loads(data.decode())

def write_vault(entries, key, salt):
    nonce, ciphertext = encrypt(entries, key)
    data = {
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }
    with open(VAULT_PATH, "w") as f:
        json.dump(data, f, indent=2)


def open_vault(master_password):
    try:
        with open(VAULT_PATH, "r") as f:
            data = json.load(f)
        salt = base64.b64decode(data["salt"])
        nonce = base64.b64decode(data["nonce"])
        ciphertext = base64.b64decode(data["ciphertext"])
        key = derive_key(master_password, salt)
        entries = decrypt(nonce, ciphertext, key)
        return entries, key, salt
    except InvalidTag:
        sys.exit("Wrong master password!")

def ask_master(confirm=False):
    pw = getpass.getpass("Master password: ")
    if confirm:
        if len(pw) < 8:
            sys.exit("Master password kam az kam 8 characters ka rakhein.")
        if getpass.getpass("Dobara likhein: ") != pw:
            sys.exit("Passwords match nahi hue.")
    return pw


def unlock():
    if not os.path.exists(VAULT_PATH):
        sys.exit("Vault nahi mila. Pehle init chalayein.")
    return open_vault(ask_master())


def generate_password(length=16):
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(secrets.choice(chars) for _ in range(length))


def cmd_init():
    if os.path.exists(VAULT_PATH):
        sys.exit("Vault pehle se maujood hai.")
    master = ask_master(confirm=True)
    salt = os.urandom(16)
    key = derive_key(master, salt)
    write_vault([], key, salt)
    print("Naya vault ban gaya!")


def cmd_add(service, username, use_generate):
    entries, key, salt = unlock()
    if use_generate:
        password = generate_password()
        print("Generated password:", password)
    else:
        password = getpass.getpass("Entry ka password: ")
    entries.append({"service": service, "username": username, "password": password})
    write_vault(entries, key, salt)
    print("Save ho gaya!")


def cmd_get(service):
    entries, key, salt = unlock()
    found = False
    for e in entries:
        if e["service"].lower() == service.lower():
            print("Service :", e["service"])
            print("Username:", e["username"])
            print("Password:", e["password"])
            found = True
    if not found:
        print("Nahi mila.")


def cmd_search(query):
    entries, key, salt = unlock()
    found = False
    for e in entries:
        if query.lower() in e["service"].lower() or query.lower() in e["username"].lower():
            print(e["service"], "|", e["username"])
            found = True
    if not found:
        print("Koi match nahi mila.")


def cmd_list():
    entries, key, salt = unlock()
    if not entries:
        print("Vault khali hai.")
    for i, e in enumerate(entries, 1):
        print(i, e["service"], "|", e["username"])


def cmd_delete(service):
    entries, key, salt = unlock()
    new_entries = [e for e in entries if e["service"].lower() != service.lower()]
    if len(new_entries) == len(entries):
        sys.exit("Koi entry delete nahi hui.")
    write_vault(new_entries, key, salt)
    print("Delete ho gaya!")

def main():
    if len(sys.argv) < 2:
        print("Commands: init | add | get | search | list | delete")
        return

    cmd = sys.argv[1]
    if cmd == "init":
        cmd_init()
    elif cmd == "add" and len(sys.argv) >= 4:
        cmd_add(sys.argv[2], sys.argv[3], "--generate" in sys.argv)
    elif cmd == "get" and len(sys.argv) >= 3:
        cmd_get(sys.argv[2])
    elif cmd == "search" and len(sys.argv) >= 3:
        cmd_search(sys.argv[2])
    elif cmd == "list":
        cmd_list()
    elif cmd == "delete" and len(sys.argv) >= 3:
        cmd_delete(sys.argv[2])
    else:
        print("Galat command. Dobara check karein.")


if __name__ == "__main__":
    main()
