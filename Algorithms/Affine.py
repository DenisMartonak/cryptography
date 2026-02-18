import unicodedata
from math import gcd

ABECEDA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
CISLA = "0123456789"
CISLA_NORMALISED = ["XNULAX", "XJEDNAX", "XDVAX", "XTRIX", "XSTYRIX", "XPATX", "XSESTX", "XSEDEMX", "XOSEMX", "XDEVATX"]
PLACEHOLDER = "XMEZERAX"   # podla zadania

def normalize_text(text: str) -> str:
    text = ''.join(ch for ch in unicodedata.normalize("NFD", text.upper())
                   if unicodedata.category(ch) != "Mn")
    out = []
    for ch in text:
        if ch == " ":
            out.append(PLACEHOLDER)
        elif ch in ABECEDA:
            out.append(ch)
        elif ch in CISLA:
            out.append(CISLA_NORMALISED[int(ch)])
    return "".join(out)

def mod_inverse(a: int, m: int) -> int | None:
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def encrypt_char(ch: str, a: int, b: int) -> str:
    if ch in ABECEDA:
        idx = ABECEDA.index(ch)
        return ABECEDA[(a * idx + b) % len(ABECEDA)]
    return ch

def decrypt_char(ch: str, a_inv_letters: int, b: int) -> str:
    if ch in ABECEDA:
        idx = ABECEDA.index(ch)
        return ABECEDA[(a_inv_letters * (idx - b)) % len(ABECEDA)]
    return ch

def affine_encrypt(plain: str, a: int, b: int) -> str:
    if gcd(a, len(ABECEDA)) != 1:
        raise ValueError("a must be coprime with 26 (letters)")
    normalized = normalize_text(plain)
    cipher_chars = [encrypt_char(ch, a, b) for ch in normalized]
    cipher = "".join(cipher_chars)
    blocks = [cipher[i:i+5] for i in range(0, len(cipher), 5)]
    return " ".join(blocks)

def affine_decrypt(cipher_with_blocks: str, a: int, b: int) -> str:
    if gcd(a, len(ABECEDA)) != 1:
        raise ValueError("a must be coprime with 26 (letters)")
    cipher = cipher_with_blocks.replace(" ", "")
    a_inv_letters = mod_inverse(a, len(ABECEDA))
    if a_inv_letters is None:
        raise ValueError("No modular inverse for 'a' in letters set.")
    plain_chars = [decrypt_char(ch, a_inv_letters, b) for ch in cipher]
    decrypted = "".join(plain_chars)
    final = decrypted.replace(PLACEHOLDER, " ")
    # Replace CISLA_NORMALISED na normal cisla
    for i, token in enumerate(CISLA_NORMALISED):
        final = final.replace(token, str(i))
    return final

def print_zdrojova(a: int, b: int) -> str:
    str_final = ""
    for ch in ABECEDA:
        str_final += ch + " = " + encrypt_char(ch, a, b) + "\n"
    return str_final
