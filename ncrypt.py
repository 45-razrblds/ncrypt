#!/usr/bin/env python3
import os
import sys
import base64
import logging
from getpass import getpass
from cryptography.fernet import Fernet
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

# Logging-Konfiguration
class LogFormatter(logging.Formatter):
    COLORS = {
        'FTL': '\033[41;30m',  # rot Hintergrund, schwarz Text
        'ERR': '\033[91m',
        'WRN': '\033[93m',
        'LOG': '\033[94m',
    }
    RESET = '\033[0m'

    def format(self, record):
        prefix = record.msg.split(":")[0]
        color = self.COLORS.get(prefix, "")
        msg = super().format(record)
        return f"{color}{msg}{self.RESET}"

logger = logging.getLogger()
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(LogFormatter("%(message)s"))
logger.addHandler(handler)

def log(msg, level="LOG", code="000"):
    logger.info(f"[{level}] {level}:{code} - {msg}")

# --- AES Funktionen ---
def aes_encrypt():
    log("Starte AES-Verschlüsselung", "LOG", "AES101")
    password = getpass("Passwort: ")
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32, count=100000)
    plaintext = input("Klartext: ").encode()
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    with open("aes_encrypted.bin", "wb") as f:
        f.write(salt + cipher.nonce + tag + ciphertext)
    log("Datei erfolgreich verschlüsselt als aes_encrypted.bin", "LOG", "AES102")

def aes_decrypt():
    log("Starte AES-Entschlüsselung", "LOG", "AES201")
    password = getpass("Passwort: ")
    try:
        with open("aes_encrypted.bin", "rb") as f:
            data = f.read()
        salt, nonce, tag, ciphertext = data[:16], data[16:32], data[32:48], data[48:]
        key = PBKDF2(password, salt, dkLen=32, count=100000)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        print(f"Entschlüsselt: {plaintext.decode()}")
        log("Entschlüsselung erfolgreich", "LOG", "AES202")
    except Exception as e:
        log(f"Fehler bei AES-Entschlüsselung: {e}", "ERR", "AESE99")

# --- Menüführung ---
def aes_menu():
    while True:
        print("\n[AES]")
        print("[1] Encrypt")
        print("[2] Decrypt")
        print("[0] Zurück")
        choice = input("> ")
        if choice == "1":
            aes_encrypt()
        elif choice == "2":
            aes_decrypt()
        elif choice == "0":
            break
        else:
            log("Ungültige Eingabe", "WRN", "AES900")

def main_menu():
    while True:
        print("\n---- NCRPYT ----")
        print("[1] AES")
        print("[2] Fernet")
        print("[3] RSA")
        print("[0] Beenden")
        choice = input("> ")
        if choice == "1":
            aes_menu()
        elif choice == "2":
            log("Fernet-Modul noch nicht implementiert", "WRN", "FER000")
        elif choice == "3":
            log("RSA-Modul noch nicht implementiert", "WRN", "RSA000")
        elif choice == "0":
            log("Beendet", "LOG", "SYS000")
            sys.exit(0)
        else:
            log("Ungültige Eingabe", "WRN", "SYS901")

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        log("Manuell abgebrochen", "WRN", "SYS902")
        sys.exit(1)
