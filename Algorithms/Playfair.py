import unicodedata

NUMBERS = {
    '0': 'XNULAX',
    '1': 'XJEDNAX',
    '2': 'XDVAX',
    '3': 'XTRIX',
    '4': 'XSTYRIX',
    '5': 'XPATX',
    '6': 'XSESTX',
    '7': 'XSEDEMX',
    '8': 'XOSEMX',
    '9': 'XDEVATX'
}

SPECIAL = {
    ' ': 'XMEZERAX'
}

REVERSE_NUMBERS = {v: k for k, v in NUMBERS.items()}
REVERSE_SPECIAL = {v: k for k, v in SPECIAL.items()}

def remove_diacritics(text: str) -> str:
    return ''.join(
        c for c in unicodedata.normalize('NFKD', text)
        if unicodedata.category(c) != 'Mn'
    )

def normalize_for_language(text: str, language: str) -> str:
    text = text.upper()
    if language == "EN":
        text = text.replace("J", "I")
        text = text.replace("Q", "K")
    elif language == "CZ":
        text = remove_diacritics(text)
        text = text.replace("Q", "K")
        text = text.replace("W", "V")
    else:
        raise ValueError("Unsupported language, use 'EN' or 'CZ'.")
    return text

def remove_fillers(decrypted: str, fillers=('X', 'Q', 'W')) -> str:
    res = []
    i = 0
    while i < len(decrypted):
        if (
            i > 0
            and i < len(decrypted) - 1
            and decrypted[i] in fillers
            and decrypted[i - 1] == decrypted[i + 1]
        ):
            i += 1
            continue
        res.append(decrypted[i])
        i += 1

    if res and res[-1] in fillers:
        res.pop()

    return ''.join(res)



def table_construct(key: str, language: str):
    if language == "EN":
        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    else:
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVXYZ"

    key = remove_diacritics(key).upper()
    
    if language == "EN":
        key = key.replace("J", "I").replace("Q", "K")
    elif language == "CZ":
        key = key.replace("Q", "K").replace("W", "V")
    
    key = ''.join([ch for ch in key if ch in alphabet])
    
    seen = set()
    filtered_key = ''.join([c for c in key if not (c in seen or seen.add(c))])

    full = filtered_key + ''.join([c for c in alphabet if c not in filtered_key])
    full = full[:25]
    table = [list(full[i:i + 5]) for i in range(0, 25, 5)]
    return table


def find_in_table(table, char):
    for row in range(5):
        for col in range(5):
            if table[row][col] == char:
                return row, col
    return None, None

def text_process(text: str, key: str):
    if not key or not key.strip():
        key = "DEFAULT"

    for digit, replacement in NUMBERS.items():
        text = text.replace(digit, replacement)

    for char, replacement in SPECIAL.items():
        text = text.replace(char, replacement)

    filtered = ''.join(ch for ch in text if ch.isalpha())

    return filtered, key.upper()

def decrypt_text_process(text: str):
    text = text.replace(" ", "")

    replacements = {**REVERSE_SPECIAL, **REVERSE_NUMBERS}

    for seq in sorted(replacements, key=len, reverse=True):
        text = text.replace(seq, replacements[seq])

    return text

def normalize_playfair(text: str):
    filtered = ''.join(ch.upper() for ch in text if ch.isalpha())
    filtered = remove_diacritics(filtered)

    fillers = ['X', 'Q', 'W']
    current_filler = 0
    bigrams = []
    i = 0

    while i < len(filtered):
        a = filtered[i]

        if i + 1 >= len(filtered):
            filler = fillers[current_filler]
            while a == filler and current_filler < len(fillers) - 1:
                current_filler += 1
                filler = fillers[current_filler]
            bigrams.append(a + filler)
            break

        b = filtered[i + 1]

        if a == b:
            filler = fillers[current_filler]
            while filler == a and current_filler < len(fillers) - 1:
                current_filler += 1
                filler = fillers[current_filler]
            bigrams.append(a + filler)
            current_filler = (current_filler + 1) % len(fillers)
            i += 1
        else:
            bigrams.append(a + b)
            i += 2

    return bigrams

def format_in_groups(text: str, group_size: int = 5) -> str:
    return ' '.join([text[i:i + group_size] for i in range(0, len(text), group_size)])

def playfair_encrypt(text, table, language):
    text = normalize_for_language(text, language)
    bigrams = normalize_playfair(text)
    result = ''

    for pair in bigrams:
        a, b = pair[0], pair[1]
        ra, ca = find_in_table(table, a)
        rb, cb = find_in_table(table, b)

        if None in (ra, ca, rb, cb):
            continue

        if ra == rb:  # Rovnaky riadok
            result += table[ra][(ca + 1) % 5]
            result += table[rb][(cb + 1) % 5]
        elif ca == cb:  # Rovnaky stlpec
            result += table[(ra + 1) % 5][ca]
            result += table[(rb + 1) % 5][cb]
        else:  # Obdlznik
            result += table[ra][cb]
            result += table[rb][ca]

    return result

def encrypt_playfair_full(text, key, language):
    processed_text, key = text_process(text, key)

    table = table_construct(key, language)

    normalized_text = normalize_for_language(processed_text, language)
    bigrams = normalize_playfair(normalized_text)

    encrypted = playfair_encrypt(processed_text, table, language)

    encrypted_formatted = format_in_groups(encrypted, 5)

    filtered_bigrams = ' '.join(bigrams)

    return encrypted_formatted, table, filtered_bigrams

def playfair_decrypt(cipher, table, language):
    cipher = ''.join(ch for ch in cipher if ch.isalpha())
    result = ''

    for i in range(0, len(cipher), 2):
        if i + 1 >= len(cipher):
            break

        a, b = cipher[i], cipher[i + 1]
        ra, ca = find_in_table(table, a)
        rb, cb = find_in_table(table, b)

        if ra is None or rb is None:
            continue

        if ra == rb:  # Rovnaký riadok
            result += table[ra][(ca - 1) % 5]
            result += table[rb][(cb - 1) % 5]
        elif ca == cb:  # Rovnaky stlpec
            result += table[(ra - 1) % 5][ca]
            result += table[(rb - 1) % 5][cb]
        else:  # Obdlznik
            result += table[ra][cb]
            result += table[rb][ca]

    return result

def decrypt_playfair_full(cipher, key, language):
    if not key or not key.strip():
        key = "DEFAULT"

    key = normalize_for_language(key, language)
    key = key.upper()

    table = table_construct(key, language)

    decrypted = playfair_decrypt(cipher, table, language)

    cleaned = remove_fillers(decrypted)

    decoded = decrypt_text_process(cleaned)

    decrypted_formatted = format_in_groups(decrypted, 2)

    return decoded, table, decrypted_formatted