import random
import string
import unicodedata

NUMBER_TO_WORD = {
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

WORD_TO_NUMBER = {v: k for k, v in NUMBER_TO_WORD.items()}

def remove_diacritics(text: str) -> str:
    bez_diakritiky = unicodedata.normalize('NFKD', text)
    return ''.join([c for c in bez_diakritiky if not unicodedata.combining(c)]).upper()

def generate_random_alphabet(mode: str) -> str:
    if mode == "6x6":
        # 6x6 grid
        chars = list(string.ascii_uppercase + string.digits)
    else:
        # 5x5 grid 
        if mode == "EN":
            chars = list(string.ascii_uppercase.replace('J', ''))
        else:  # CZ
            chars = list(string.ascii_uppercase.replace('W', ''))

    random.shuffle(chars)
    return ''.join(chars)

def create_polybius_square(alphabet: str, mode: str):
    size = 6 if mode == "6x6" else 5
    square = []

    for i in range(size):
        row = []
        for j in range(size):
            idx = i * size + j
            if idx < len(alphabet):
                row.append(alphabet[idx])
            else:
                row.append('')
        square.append(row)

    return square

def get_headers(mode: str):
    if mode == "6x6":
        return ['A', 'D', 'F', 'G', 'V', 'X']
    else:
        return ['A', 'D', 'F', 'G', 'X']

def preprocess_plaintext(text: str, mode: str) -> str:
    if mode == "CZ":
        text = remove_diacritics(text)

    text = text.replace(' ', 'XMEZERAX').upper()

    if mode in ["EN", "CZ"]:
        for digit, czech_word in NUMBER_TO_WORD.items():
            text = text.replace(digit, czech_word)

    if mode == "EN":
        text = text.replace('J', 'I')
    elif mode == "CZ":
        text = text.replace('W', 'V') 

    valid_chars = set()
    if mode == "6x6":
        valid_chars = set(string.ascii_uppercase + string.digits)
    else:
        if mode == "EN":
            valid_chars = set(string.ascii_uppercase.replace('J', ''))
        else:
            valid_chars = set(string.ascii_uppercase.replace('W', ''))

    text = ''.join([c for c in text if c in valid_chars])

    return text

def encode_with_polybius(text: str, alphabet: str, mode: str) -> str:
    headers = get_headers(mode)
    size = len(headers)
    encoded = ""

    char_to_pos = {}
    for i in range(size):
        for j in range(size):
            idx = i * size + j
            if idx < len(alphabet):
                char_to_pos[alphabet[idx]] = (i, j)

    for char in text:
        if char in char_to_pos:
            row, col = char_to_pos[char]
            encoded += headers[row] + headers[col]

    return encoded

def decode_with_polybius(encoded_text: str, alphabet: str, mode: str) -> str:
    headers = get_headers(mode)
    size = len(headers)
    decoded = ""

    pos_to_char = {}
    for i in range(size):
        for j in range(size):
            idx = i * size + j
            if idx < len(alphabet):
                pos_to_char[(i, j)] = alphabet[idx]

    for i in range(0, len(encoded_text), 2):
        if i + 1 < len(encoded_text):
            row_letter = encoded_text[i]
            col_letter = encoded_text[i + 1]

            if row_letter in headers and col_letter in headers:
                row = headers.index(row_letter)
                col = headers.index(col_letter)

                if (row, col) in pos_to_char:
                    decoded += pos_to_char[(row, col)]

    if mode in ["EN", "CZ"]:
        for czech_word, digit in WORD_TO_NUMBER.items():
            decoded = decoded.replace(czech_word, digit)

    decoded = decoded.replace('XMEZERAX', ' ')

    return decoded

def columnar_transposition_encrypt(text: str, keyword: str) -> str:
    keyword = keyword.upper()
    key_length = len(keyword)

    if key_length == 0:
        return text

    sorted_keyword = sorted(enumerate(keyword), key=lambda x: x[1])
    column_order = [x[0] for x in sorted_keyword]

    rows = []
    for i in range(0, len(text), key_length):
        rows.append(text[i:i + key_length])

    ciphertext = ""
    for col_idx in column_order:
        for row in rows:
            if col_idx < len(row):
                ciphertext += row[col_idx]

    return ciphertext

def columnar_transposition_decrypt(ciphertext: str, keyword: str) -> str:
    keyword = keyword.upper()
    key_length = len(keyword)

    if key_length == 0:
        return ciphertext

    total_chars = len(ciphertext)
    full_rows = total_chars // key_length
    extra_chars = total_chars % key_length

    column_lengths = []
    for i in range(key_length):
        if i < extra_chars:
            column_lengths.append(full_rows + 1)
        else:
            column_lengths.append(full_rows)

    sorted_keyword = sorted(enumerate(keyword), key=lambda x: (x[1], x[0]))
    column_order = [x[0] for x in sorted_keyword]

    columns = {}
    idx = 0
    for col_idx in column_order:
        col_len = column_lengths[col_idx]
        columns[col_idx] = ciphertext[idx:idx + col_len]
        idx += col_len

    plaintext = ""
    num_rows = full_rows + (1 if extra_chars > 0 else 0)
    for row in range(num_rows):
        for col in range(key_length):
            if row < len(columns[col]):
                plaintext += columns[col][row]

    return plaintext


def adfgvx_encrypt(plaintext: str, keyword: str, alphabet: str, mode: str):
    text = preprocess_plaintext(plaintext, mode)
    encoded = encode_with_polybius(text, alphabet, mode)
    ciphertext = columnar_transposition_encrypt(encoded, keyword)
    formatted = ' '.join([ciphertext[i:i+5] for i in range(0, len(ciphertext), 5)])
    table = create_polybius_square(alphabet, mode)

    return formatted, table

def adfgvx_decrypt(ciphertext: str, keyword: str, alphabet: str, mode: str):
    ciphertext = ciphertext.replace(' ', '')
    transposed = columnar_transposition_decrypt(ciphertext, keyword)
    plaintext = decode_with_polybius(transposed, alphabet, mode)
    table = create_polybius_square(alphabet, mode)

    return plaintext, table

def alphabet_from_table(table) -> str:
    alphabet = ""
    for row in table:
        for char in row:
            if char:
                alphabet += char
    return alphabet
