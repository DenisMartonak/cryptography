# Cryptography App

A Python-based graphical user interface (GUI) application for learning, testing, and demonstrating various classic and modern cryptographic algorithms. This project provides an easy-to-use platform for encrypting, decrypting, signing, and verifying data using algorithms like Affine, Playfair, ADFGVX, RSA, and DSA.

## Features

The application features a tabbed interface allowing users to switch between five different cryptographic modules:

### 1. Affine Cipher
* **Encryption & Decryption**: Transforms text using the linear function $E(x) = (ax + b) \mod m$.
* **Input Validation**: Ensures parameter 'a' is coprime to the alphabet length (26).
* **Automatic Normalization**: Removes diacritics and handles non-alphabetic characters.
* **Randomization**: fast generation of valid 'a' and 'b' keys.
* **Visual Feedback**: Displays the source alphabet mapping ("Zdrojova abeceda").

### 2. Playfair Cipher
* **Language Support**: Switch between **English** (J=I) and **Czech** (W=V) modes.
* **Table Visualization**: View the generated 5x5 key matrix directly in the GUI.
* **Bigram Processing**: Automatically handles duplicate letters (adding 'X', 'Q', or 'W' fillers) and odd-length strings.
* **Custom Keys**: Input your own keyword to generate the cipher table.

### 3. ADFGVX Cipher
* **Modes**:
    * **5x5 (English)**: Standard alphabet (J merged).
    * **5x5 (Czech)**: Czech alphabet (W removed).
    * **6x6**: Extended alphabet including digits 0-9.
* **Table Generation**: Choose between a **Random** table or **Manual** entry to customize the Polybius square.
* **Transposition**: Implements columnar transposition using a keyword.

### 4. RSA (Rivest–Shamir–Adleman)
* **Key Generation**: Generates large prime numbers ($p, q$) and calculates public/private key pairs ($n, e$ and $n, d$).
* **Block Encryption**: Converts text to binary, splits it into blocks, and encrypts strictly using RSA math ($m^e \mod n$).
* **Detailed Logs**: Displays internal values like $\phi(n)$, block conversions, and the raw numeric output of the encryption process.

### 5. DSA (Digital Signature Algorithm)
* **File Signing**: Sign any arbitrary file using RSA keys and SHA3-512 hashing.
* **Verification**: Verify the integrity of signed archives (.zip containing the document and .sign file).
* **Export/Import**: Save and load Private/Public keys and export signed packages.

## Prerequisites

* **Python 3.x**
* **PyQt5**: Used for the graphical user interface.

## Installation

1.  **Clone the repository** (or extract the project folder):
    ```bash
    git clone <repository-url>
    cd cryptography
    ```

2.  **Install the dependencies**:
    ```bash
    pip install PyQt5
    ```

## Usage

1.  **Run the application**:
    ```bash
    python main.py
    ```

2.  **Navigate the GUI**:
    * Use the sidebar buttons to switch between algorithms.
    * **Affine/Playfair/ADFGVX**: Enter your text and keys, then click **Encrypt** or **Decrypt**.
    * **RSA**: Click **Generate Keys** first, then input text to encrypt. Copy the numeric output to the input box to test decryption.
    * **DSA**: 
        1. Generate and save keys.
        2. Load a file to sign and a private key.
        3. Click **Sign & Export** to create a signed ZIP.
        4. To verify, load the ZIP and the corresponding public key.

## Project Structure

* **`main.py`**: The entry point of the application. Handles GUI setup and event linking.
* **`main.ui`**: The visual layout file (XML format) for the PyQt interface.
* **`Algorithms/`**: Contains the logic for each cipher.
    * `Affine.py`: Math and logic for the Affine cipher.
    * `Playfair.py`: Matrix construction and bigram rules.
    * `ADFGVX.py`: Polybius square and transposition logic.
    * `RSA.py`: Prime generation and modular exponentiation.
    * `DSA.py`: File hashing (SHA3-512) and signature handling.
* **`resources.py`**: Helper resources (if applicable).

## Authors

* Denis Martonak
