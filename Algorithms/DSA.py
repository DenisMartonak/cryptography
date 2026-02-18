import hashlib
import base64
import json
import zipfile
import os
import Algorithms.RSA

def generate_keys():
    return Algorithms.RSA.generate_rsa_keys()

def save_keys_to_files(keys, priv_path, pub_path):
    priv_data = json.dumps({'n': keys['n'], 'd': keys['d']})
    priv_b64 = base64.b64encode(priv_data.encode()).decode()
    priv_content = f"RSA {priv_b64}"

    pub_data = json.dumps({'n': keys['n'], 'e': keys['e']})
    pub_b64 = base64.b64encode(pub_data.encode()).decode()
    pub_content = f"RSA {pub_b64}"

    with open(priv_path, 'w', encoding='utf-8') as f:
        f.write(priv_content)
    
    with open(pub_path, 'w', encoding='utf-8') as f:
        f.write(pub_content)

def load_private_key(path):
    with open(path, 'r', encoding='utf-8') as f:
        content = f.read().strip()
    
    if not content.startswith("RSA "):
        raise ValueError("Invalid file format. Header 'RSA' missing.")
    
    b64_str = content.split(" ", 1)[1]
    data = json.loads(base64.b64decode(b64_str).decode())
    return (data['n'], data['d'])

def load_public_key(path):
    with open(path, 'r', encoding='utf-8') as f:
        content = f.read().strip()
    
    if not content.startswith("RSA "):
        raise ValueError("Invalid file format. Header 'RSA' missing.")
    
    b64_str = content.split(" ", 1)[1]
    data = json.loads(base64.b64decode(b64_str).decode())
    return (data['n'], data['e'])

def sign_file(file_path, private_key, output_zip_path):
    sha3 = hashlib.sha3_512()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            sha3.update(chunk)
    file_hash_hex = sha3.hexdigest()

    numeric_blocks, _ = Algorithms.RSA.text_to_numeric(file_hash_hex)
    encrypted_blocks = Algorithms.RSA.rsa_encrypt_blocks(numeric_blocks, private_key)

    signature_json = json.dumps(encrypted_blocks)
    signature_b64 = base64.b64encode(signature_json.encode()).decode()
    signature_content = f"RSA_SHA3-512 {signature_b64}"

    base_filename = os.path.basename(file_path)
    sign_filename = base_filename + ".sign"

    with zipfile.ZipFile(output_zip_path, 'w') as zipf:
        zipf.write(file_path, base_filename)
        zipf.writestr(sign_filename, signature_content)

    return True

def verify_zip(zip_path, public_key):
    with zipfile.ZipFile(zip_path, 'r') as zipf:
        file_names = zipf.namelist()
        
        sign_file = next((f for f in file_names if f.endswith('.sign')), None)
        if not sign_file:
            raise FileNotFoundError("No .sign file found in the archive.")
        
        doc_file = next((f for f in file_names if f != sign_file), None)
        if not doc_file:
            raise FileNotFoundError("Original document not found in the archive.")

        sig_content = zipf.read(sign_file).decode('utf-8').strip()
        if not sig_content.startswith("RSA_SHA3-512 "):
            raise ValueError("Invalid signature file header.")
        
        b64_sig = sig_content.split(" ", 1)[1]
        encrypted_blocks = json.loads(base64.b64decode(b64_sig).decode())

        decrypted_blocks = Algorithms.RSA.rsa_decrypt_blocks(encrypted_blocks, public_key)
        decrypted_hash_hex = Algorithms.RSA.numeric_to_text(decrypted_blocks)

        sha3 = hashlib.sha3_512()
        with zipf.open(doc_file) as f:
            while chunk := f.read(8192):
                sha3.update(chunk)
        calculated_hash_hex = sha3.hexdigest()

        is_valid = (decrypted_hash_hex == calculated_hash_hex)
        
        return is_valid, decrypted_hash_hex, calculated_hash_hex