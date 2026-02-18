import random
import math
import unicodedata

BLOCK_SIZE_CHARS = 8
BITS_PER_CHAR = 8

CHAR_MAP = {chr(i): format(i, f'0{BITS_PER_CHAR}b') for i in range(256)}
REVERSE_MAP = {v: k for k, v in CHAR_MAP.items()}

BLOCK_BIT_SIZE = BLOCK_SIZE_CHARS * BITS_PER_CHAR

def remove_diacritics(text: str) -> str:
    return ''.join(
        c for c in unicodedata.normalize('NFKD', text)
        if unicodedata.category(c) != 'Mn'
    )
def is_prime(n, k=10):
    """Miller-Rabin"""
    if n < 2: return False
    if n == 2 or n == 3: return True
    if n % 2 == 0: return False

    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(digits):
    min_val = 10 ** (digits - 1)
    max_val = (10 ** digits) - 1

    while True:
        candidate = random.randint(min_val, max_val)
        if candidate % 2 == 0:
            continue
        if is_prime(candidate):
            return candidate


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def mod_inverse(e, phi):
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd_val, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd_val, x, y

    gcd_val, x, _ = extended_gcd(e, phi)
    if gcd_val != 1:
        raise ValueError("Modular inverse does not exist")
    return (x % phi + phi) % phi

def generate_rsa_keys():
    digits = 14

    p = generate_prime(digits)
    q = generate_prime(digits)
    while p == q:
        q = generate_prime(digits)

    n = p * q
    phi = (p - 1) * (q - 1)

    while True:
        e = random.randrange(2, phi)
        if gcd(e, phi) == 1:
            break

    d = mod_inverse(e, phi)

    return {
        'p': p, 'q': q,
        'n': n, 'phi': phi,
        'e': e, 'd': d,
        'digits': digits
    }

def text_to_numeric(text):
    text = remove_diacritics(text)

    full_binary_string = ""
    for char in text:
        bits = CHAR_MAP.get(char, CHAR_MAP.get('?', '00111111'))
        full_binary_string += bits

    remainder = len(full_binary_string) % BLOCK_BIT_SIZE
    if remainder != 0:
        padding_needed = BLOCK_BIT_SIZE - remainder
        full_binary_string = full_binary_string.ljust(len(full_binary_string) + padding_needed, '0')

    numeric_blocks = []
    for i in range(0, len(full_binary_string), BLOCK_BIT_SIZE):
        chunk = full_binary_string[i: i + BLOCK_BIT_SIZE]
        number = int(chunk, 2)
        numeric_blocks.append(number)

    return numeric_blocks, full_binary_string


def numeric_to_text(numeric_blocks):
    decoded_text = ""

    for number in numeric_blocks:
        binary_chunk = format(number, f'0{BLOCK_BIT_SIZE}b')

        for i in range(0, len(binary_chunk), BITS_PER_CHAR):
            char_bits = binary_chunk[i: i + BITS_PER_CHAR]

            char = REVERSE_MAP.get(char_bits, '')

            if char == '\x00':
                continue

            decoded_text += char

    return decoded_text
def rsa_encrypt_blocks(numeric_blocks, public_key):
    n, e = public_key
    return [pow(m, e, n) for m in numeric_blocks]


def rsa_decrypt_blocks(cipher_blocks, private_key):
    n, d = private_key
    return [pow(c, d, n) for c in cipher_blocks]