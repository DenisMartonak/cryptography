import os
import sys
import datetime
import random
from PyQt5.QtWidgets import QApplication, QMainWindow, QTableWidgetItem, QHeaderView, QTableWidget, QFileDialog
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont
from PyQt5 import uic
import resources

from Algorithms.Affine import normalize_text, affine_decrypt, affine_encrypt, print_zdrojova
from Algorithms.Playfair import decrypt_playfair_full, encrypt_playfair_full
from Algorithms.ADFGVX import generate_random_alphabet, adfgvx_encrypt, adfgvx_decrypt, create_polybius_square, get_headers, alphabet_from_table
import Algorithms.RSA
import Algorithms.DSA

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        ui_path = os.path.join(os.path.dirname(__file__), "main.ui")
        uic.loadUi(ui_path, self)

        self.Affine_Button.clicked.connect(lambda: self.switch_page(0, self.Affine_Button))
        self.Playfair_Button.clicked.connect(lambda: self.switch_page(1, self.Playfair_Button))
        self.ADFGVX_Button.clicked.connect(lambda: self.switch_page(2, self.ADFGVX_Button))
        self.RSA_Button.clicked.connect(lambda: self.switch_page(3, self.RSA_Button))
        self.DSA_Button.clicked.connect(lambda: self.switch_page(4, self.DSA_Button))

        self.init_affine()
        self.init_playfair()
        self.init_adfgvx()
        self.init_rsa()
        self.init_dsa()

        self.switch_page(0, self.Affine_Button)

    def switch_page(self, index, active_button):
        self.stackedWidget.setCurrentIndex(index)
        active_style = "background-color: #6a0dad"
        inactive_style = "background-color: #2d2d2d"

        buttons = [self.Affine_Button, self.Playfair_Button, self.ADFGVX_Button, self.RSA_Button, self.DSA_Button]

        for btn in buttons:
            if btn == active_button:
                btn.setStyleSheet(active_style)
            else:
                btn.setStyleSheet(inactive_style)

    def init_affine(self):
        self.encryptButton_Affine.clicked.connect(self.on_encrypt_Affine)
        self.decryptButton_Affine.clicked.connect(self.on_decrypt_Affine)
        self.randomA_Affine.clicked.connect(self.on_randomA_Affine)
        self.randomB_Affine.clicked.connect(self.on_randomB_Affine)

    def init_playfair(self):
        self.language = "EN"
        self.enButton_Playfair.clicked.connect(lambda: self.playfair_language_select(self.enButton_Playfair))
        self.enButton_Playfair.clicked.connect(self.set_language_playfair_en)
        self.czButton_Playfair.clicked.connect(lambda: self.playfair_language_select(self.czButton_Playfair))
        self.czButton_Playfair.clicked.connect(self.set_language_playfair_cz)
        self.czButton_Playfair.setStyleSheet("background-color: none")

        self.table_Playfair.setEditTriggers(QTableWidget.NoEditTriggers)
        header = self.table_Playfair.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Fixed)
        vheader = self.table_Playfair.verticalHeader()
        vheader.setSectionResizeMode(QHeaderView.Fixed)

        self.encryptButton_Playfair.clicked.connect(self.on_encrypt_Playfair)
        self.decryptButton_Playfair.clicked.connect(self.on_decrypt_Playfair)

    def init_adfgvx(self):
        self.language_ADFGVX = "EN"
        self.is_manual_table = False
        self.current_alphabet = ""

        self.enButton_ADFGVX.clicked.connect(lambda: self.adfgvx_language_select(self.enButton_ADFGVX))
        self.enButton_ADFGVX.clicked.connect(self.set_language_adfgvx_en)
        self.czButton_ADFGVX.clicked.connect(lambda: self.adfgvx_language_select(self.czButton_ADFGVX))
        self.czButton_ADFGVX.clicked.connect(self.set_language_adfgvx_cz)
        self.czButton_ADFGVX.setStyleSheet("background-color: none")
        self.x6Layout.clicked.connect(lambda: self.adfgvx_language_select(self.x6Layout))
        self.x6Layout.clicked.connect(self.set_language_adfgvx_6x6)

        self.RandomTable.clicked.connect(lambda: self.adfgvx_table_select(self.RandomTable))
        self.RandomTable.clicked.connect(self.on_random_table_selected)
        self.ManualTable.clicked.connect(lambda: self.adfgvx_table_select(self.ManualTable))
        self.ManualTable.clicked.connect(self.on_manual_table_selected)

        self.EncryptADFGVX.clicked.connect(self.on_encrypt_ADFGVX)
        self.DecryptADFGVX.clicked.connect(self.on_decrypt_ADFGVX)
        self.ADFGVXTable.setEditTriggers(QTableWidget.NoEditTriggers)
        self.setup_adfgvx_table()

    def init_rsa(self):
        self.rsa_gen_keys_btn.clicked.connect(self.on_rsa_generate)
        self.rsa_encrypt_btn.clicked.connect(self.on_rsa_encrypt)
        self.rsa_decrypt_btn.clicked.connect(self.on_rsa_decrypt)

        mono_font = QFont("Consolas", 24)
        mono_font.setStyleHint(QFont.Monospace)
        self.rsa_keys_log.setFont(mono_font)
        mono_font = QFont("Consolas", 12)
        self.rsa_output_log.setFont(mono_font)
        self.rsa_plain_input.setFont(mono_font)
        self.rsa_pub_key_input.setFont(mono_font)
        self.rsa_priv_key_input.setFont(mono_font)

    def init_dsa(self):
        self.dsa_current_keys = None
        self.dsa_private_key_loaded = None
        self.dsa_public_key_loaded = None
        self.dsa_file_to_sign_path = None
        self.dsa_zip_to_verify_path = None

        self.DSA_GenerateKeys.clicked.connect(self.dsa_generate_keys)
        self.DSA_SaveKeys.clicked.connect(self.dsa_save_keys)

        self.DSA_LoadFile.clicked.connect(self.dsa_load_document)
        self.DSA_LoadPriv.clicked.connect(self.dsa_load_private_key_file)
        self.DSA_Sign.clicked.connect(self.dsa_sign_and_export)

        self.DSA_LoadZip.clicked.connect(self.dsa_load_zip_file)
        self.DSA_LoadPub.clicked.connect(self.dsa_load_public_key_file)
        self.DSA_Verify.clicked.connect(self.dsa_verify_signature)

    def dsa_log(self, message):
        if hasattr(self.DSA_KeyOutput, 'toPlainText'):
            current = self.DSA_KeyOutput.toPlainText()
            self.DSA_KeyOutput.setText(current + message + "\n")
        else:
            self.DSA_KeyOutput.setText(message)

    def dsa_generate_keys(self):
        try:
            self.DSA_KeyOutput.setText("")
            QApplication.processEvents()
            self.dsa_log("Generating RSA keys... (Please wait)")
            
            self.dsa_current_keys = Algorithms.DSA.generate_keys()

            self.dsa_log(f"Keys Generated Successfully!")
            self.dsa_log(f"Modulus (n): {str(self.dsa_current_keys['n'])[:20]}...")
            self.dsa_log("Ready to export.")
        except Exception as e:
            self.dsa_log(f"Error: {e}")

    def dsa_save_keys(self):
        if not self.dsa_current_keys:
            self.dsa_log("Error: No keys generated yet.")
            return

        try:
            filename, _ = QFileDialog.getSaveFileName(self, "Save Private Key", "", "Private Key (*.priv)")
            if not filename: return

            base_path = os.path.splitext(filename)[0]
            priv_path = base_path + ".priv"
            pub_path = base_path + ".pub"

            Algorithms.DSA.save_keys_to_files(self.dsa_current_keys, priv_path, pub_path)
            self.dsa_log(f"Keys saved to:\n{priv_path}\n{pub_path}")

        except Exception as e:
            self.dsa_log(f"Error saving keys: {e}")

    def dsa_load_document(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Select File to Sign")
        if filename:
            self.dsa_file_to_sign_path = filename
            stats = os.stat(filename)
            mod_time = datetime.datetime.fromtimestamp(stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
            ext = os.path.splitext(filename)[1]

            info_text = (f"File: {os.path.basename(filename)}\n"
                         f"Type: {ext}\n"
                         f"Size: {stats.st_size} bytes\n"
                         f"Modified: {mod_time}")
            
            self.DSA_FileInfo.setText(info_text)

    def dsa_load_private_key_file(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Load Private Key", "", "Private Key (*.priv)")
        if filename:
            try:
                self.dsa_private_key_loaded = Algorithms.DSA.load_private_key(filename)
                self.dsa_log(f"Private key loaded: {os.path.basename(filename)}")
            except Exception as e:
                self.dsa_log(f"Error loading key: {e}")

    def dsa_sign_and_export(self):
        if not self.dsa_file_to_sign_path:
            self.dsa_log("Error: No file selected.")
            return
        if not self.dsa_private_key_loaded:
            self.dsa_log("Error: No private key loaded.")
            return

        save_path, _ = QFileDialog.getSaveFileName(self, "Export Signed Archive", "", "ZIP Archive (*.zip)")
        if not save_path: return

        try:
            Algorithms.DSA.sign_file(self.dsa_file_to_sign_path, self.dsa_private_key_loaded, save_path)
            self.dsa_log(f"Successfully signed and exported:\n{save_path}")
        except Exception as e:
            self.dsa_log(f"Signing Error: {e}")

    def dsa_load_zip_file(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Select Signed Archive", "", "ZIP Archive (*.zip)")
        if filename:
            self.dsa_zip_to_verify_path = filename
            self.dsa_log(f"ZIP loaded: {os.path.basename(filename)}")
            self.DSA_Result.setText("Waiting...")
            self.DSA_Result.setStyleSheet("color: gray; font-weight: normal; font-size: 12px;")

    def dsa_load_public_key_file(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Load Public Key", "", "Public Key (*.pub)")
        if filename:
            try:
                self.dsa_public_key_loaded = Algorithms.DSA.load_public_key(filename)
                self.dsa_log(f"Public key loaded: {os.path.basename(filename)}")
            except Exception as e:
                self.dsa_log(f"Error loading key: {e}")

    def dsa_verify_signature(self):
        if not self.dsa_zip_to_verify_path or not self.dsa_public_key_loaded:
            self.dsa_log("Error: Missing ZIP or Public Key.")
            return

        try:
            is_valid, decrypted_hash, calced_hash = Algorithms.DSA.verify_zip(
                self.dsa_zip_to_verify_path,
                self.dsa_public_key_loaded
            )

            self.dsa_log(f"Decrypted Hash: {decrypted_hash[:10]}...")
            self.dsa_log(f"Calculated Hash: {calced_hash[:10]}...")

            if is_valid:
                self.DSA_Result.setText("VALID")
                self.DSA_Result.setStyleSheet("color: green; font-weight: bold; font-size: 24px;")
            else:
                self.DSA_Result.setText("INVALID")
                self.DSA_Result.setStyleSheet("color: red; font-weight: bold; font-size: 24px;")

        except Exception as e:
            self.dsa_log(f"Verification Error: {e}")
            self.DSA_Result.setText("ERROR")

    def on_rsa_generate(self):
        try:
            keys = Algorithms.RSA.generate_rsa_keys()
            log_text = (f"=== RSA KEYS GENERATED ===\n"
                        f"Digits: {keys['digits']}\n"
                        f"p = {keys['p']}\n"
                        f"q = {keys['q']}\n"
                        f"n = {keys['n']}\n"
                        f"φ = {keys['phi']}\n"
                        f"e = {keys['e']}\n"
                        f"d = {keys['d']}")
            self.rsa_keys_log.setText(log_text)
            self.rsa_pub_key_input.setText(f"{keys['n']}, {keys['e']}")
            self.rsa_priv_key_input.setText(f"{keys['n']}, {keys['d']}")
            self.rsa_output_log.setText("Keys generated successfully and auto-filled.")
        except Exception as e:
            self.rsa_output_log.setText(f"Generation Error: {str(e)}")

    def on_rsa_encrypt(self):
        try:
            text = self.rsa_plain_input.toPlainText()
            if not text:
                self.rsa_output_log.setText("Error: Please enter text to encrypt.")
                return
            try:
                n_str, e_str = self.rsa_pub_key_input.text().split(',')
                pub_key = (int(n_str), int(e_str))
            except ValueError:
                self.rsa_output_log.setText("Error: Invalid Public Key format. Expected 'n, e'.")
                return
            numeric_blocks, binary_vis = Algorithms.RSA.text_to_numeric(text)
            if any(b >= pub_key[0] for b in numeric_blocks):
                self.rsa_output_log.setText("CRITICAL ERROR: Block value > n. Please regenerate keys.")
                return
            encrypted_blocks = Algorithms.RSA.rsa_encrypt_blocks(numeric_blocks, pub_key)
            n_len = len(str(pub_key[0]))
            padded_blocks = [str(b).zfill(n_len) for b in encrypted_blocks]
            full_cipher_string = "".join(padded_blocks)
            chunk_size = 8
            formatted_chunks = [full_cipher_string[i:i + chunk_size] for
                                i in range(0, len(full_cipher_string), chunk_size)]
            result_str = " ".join(formatted_chunks)
            output = []
            output.append("ENCRYPTION OUTPUT\n")
            output.append(result_str)
            output.append("\nEncryption Details")
            output.append(f"Original Text: {text}\n")
            output.append(f"Block Length used: {n_len} digits\n")
            self.rsa_output_log.setText("\n".join(output))
        except Exception as e:
            self.rsa_output_log.setText(f"Encryption Error: {str(e)}")

    def on_rsa_decrypt(self):
        try:
            raw_input = self.rsa_plain_input.toPlainText()
            if not raw_input:
                self.rsa_output_log.setText("Error: Please enter numbers to decrypt.")
                return
            try:
                n_str, d_str = self.rsa_priv_key_input.text().split(',')
                priv_key = (int(n_str), int(d_str))
            except ValueError:
                self.rsa_output_log.setText("Error: Invalid Private Key format. Expected 'n, d'.")
                return
            clean_input = raw_input.replace(' ', '').replace('\n', '').replace('\t', '')
            n_len = len(n_str.strip())
            cipher_blocks = []
            try:
                for i in range(0, len(clean_input), n_len):
                    block_str = clean_input[i: i + n_len]
                    if not block_str: continue
                    cipher_blocks.append(int(block_str))
            except ValueError:
                self.rsa_output_log.setText(f"Error: parsing input. Ensure text length aligns with key length {n_len}.")
                return
            decrypted_numeric = Algorithms.RSA.rsa_decrypt_blocks(cipher_blocks, priv_key)
            plaintext = Algorithms.RSA.numeric_to_text(decrypted_numeric)
            output = []
            output.append("DECRYPTION OUTPUT\n")
            output.append(plaintext)
            output.append("\nDecryption Details")
            output.append(f"Reconstructed Blocks: {cipher_blocks}\n")
            self.rsa_output_log.setText("\n".join(output))
        except Exception as e:
            self.rsa_output_log.setText(f"Decryption Error: {str(e)}")

    def on_encrypt_Affine(self):
        try:
            a_input = self.aInput_Affine.toPlainText().strip()
            b_input = self.bInput_Affine.toPlainText().strip()
            string_input = self.stringInput_Affine.toPlainText().strip()
            if not (a_input.isdigit() and b_input.isdigit() and string_input):
                self.resultBox_Affine.setText("⚠ Please enter valid values.")
                return
            a, b = int(a_input), int(b_input)
            normalized = normalize_text(string_input)
            encrypted = affine_encrypt(string_input, a, b)
            self.resultBox_Affine.setText(
                f"Normalized: {normalized}\nEncrypted text: {encrypted}\n\nZdrojova abeceda:\n{print_zdrojova(a, b)}")
        except Exception as e:
            self.resultBox_Affine.setText(f"⚠ Error: {e}")

    def on_decrypt_Affine(self):
        try:
            a_input = self.aInput_Affine.toPlainText().strip()
            b_input = self.bInput_Affine.toPlainText().strip()
            string_input = self.stringInput_Affine.toPlainText().strip()
            if not (a_input.isdigit() and b_input.isdigit() and string_input):
                self.resultBox_Affine.setText("⚠ Please enter valid values.")
                return
            a, b = int(a_input), int(b_input)
            normalized = normalize_text(string_input)
            decrypted = affine_decrypt(string_input, a, b)
            self.resultBox_Affine.setText(
                f"Normalized: {normalized}\nDecrypted text: {decrypted}\n\nZdrojova abeceda:\n{print_zdrojova(a, b)}")
        except Exception as e:
            self.resultBox_Affine.setText(f"⚠ Error: {e}")

    def on_randomA_Affine(self):
        self.aInput_Affine.setText(str(random.choice([1, 3, 7, 9, 11, 17, 19, 21, 23])))

    def on_randomB_Affine(self):
        self.bInput_Affine.setText(str(random.randint(0, 25)))

    def playfair_language_select(self, active):
        buttons = [self.enButton_Playfair, self.czButton_Playfair]
        active_style = "background-color: #6a0dad; border-radius: 16px;"
        inactive_style = "background-color: none; border-radius: 16px;"
        for btn in buttons:
            if btn == active:
                btn.setStyleSheet(active_style)
            else:
                btn.setStyleSheet(inactive_style)

    def on_encrypt_Playfair(self):
        try:
            key = self.keyInput_Playfair.toPlainText().strip()
            text = self.stringInput_Playfair.toPlainText().strip()
            if not text:
                self.outputBox_Playfair.setPlainText("⚠ Enter text to encrypt.")
                return
            encrypted, table, filtered_bigrams = encrypt_playfair_full(text, key, self.language)
            output = f"Filtered text (bigrams):\n{filtered_bigrams}\n\n"
            output += f"Encrypted text:\n{encrypted}"
            self.outputBox_Playfair.setPlainText(output)
            self.update_table_widget(table)
        except Exception as e:
            self.outputBox_Playfair.setPlainText(f"⚠ Error during encryption: {e}")

    def on_decrypt_Playfair(self):
        try:
            key = self.keyInput_Playfair.toPlainText().strip()
            text = self.stringInput_Playfair.toPlainText().strip()
            if not text:
                self.outputBox_Playfair.setPlainText("⚠ Enter text to decrypt.")
                return
            decrypted, table, decrypted_bigrams = decrypt_playfair_full(text, key, self.language)
            output = f"Decrypted bigrams:\n{decrypted_bigrams}\n\n"
            output += f"Decrypted text:\n{decrypted}"
            self.outputBox_Playfair.setPlainText(output)
            self.update_table_widget(table)
        except Exception as e:
            self.outputBox_Playfair.setPlainText(f"⚠ Error during decryption: {e}")

    def update_table_widget(self, table):
        self.table_Playfair.setRowCount(5)
        self.table_Playfair.setColumnCount(5)
        for row in range(5):
            for col in range(5):
                item = QTableWidgetItem(table[row][col])
                item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self.table_Playfair.setItem(row, col, item)

    def set_language_playfair_cz(self):
        self.language = "CZ"

    def set_language_playfair_en(self):
        self.language = "EN"

    def set_language_adfgvx_cz(self):
        self.language_ADFGVX = "CZ"
        self.setup_adfgvx_table()

    def set_language_adfgvx_en(self):
        self.language_ADFGVX = "EN"
        self.setup_adfgvx_table()

    def set_language_adfgvx_6x6(self):
        self.language_ADFGVX = "6x6"
        self.setup_adfgvx_table()

    def adfgvx_language_select(self, active):
        buttons = [self.enButton_ADFGVX, self.czButton_ADFGVX, self.x6Layout]
        active_style = "background-color: #6a0dad; border-radius: 16px;"
        inactive_style = "background-color: none; border-radius: 16px;"
        for btn in buttons:
            if btn == active:
                btn.setStyleSheet(active_style)
            else:
                btn.setStyleSheet(inactive_style)

    def adfgvx_table_select(self, active):
        buttons = [self.RandomTable, self.ManualTable]
        active_style = "background-color: #6a0dad;"
        inactive_style = "background-color: none;"
        for btn in buttons:
            if btn == active:
                btn.setStyleSheet(active_style)
            else:
                btn.setStyleSheet(inactive_style)

    def setup_adfgvx_table(self):
        headers = get_headers(self.language_ADFGVX)
        size = len(headers)
        self.ADFGVXTable.setRowCount(size)
        self.ADFGVXTable.setColumnCount(size)
        self.ADFGVXTable.setHorizontalHeaderLabels(headers)
        self.ADFGVXTable.setVerticalHeaderLabels(headers)
        if not self.is_manual_table:
            self.generate_random_adfgvx_table()
        header = self.ADFGVXTable.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Fixed)
        vheader = self.ADFGVXTable.verticalHeader()
        vheader.setSectionResizeMode(QHeaderView.Fixed)

    def generate_random_adfgvx_table(self):
        alphabet = generate_random_alphabet(self.language_ADFGVX)
        self.current_alphabet = alphabet
        table = create_polybius_square(alphabet, self.language_ADFGVX)
        self.update_adfgvx_table(table)

    def update_adfgvx_table(self, table):
        size = len(table)
        self.ADFGVXTable.setRowCount(size)
        self.ADFGVXTable.setColumnCount(size)
        for row in range(size):
            for col in range(size):
                item = QTableWidgetItem(table[row][col])
                item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self.ADFGVXTable.setItem(row, col, item)

    def get_alphabet_from_table(self):
        alphabet = ""
        for row in range(self.ADFGVXTable.rowCount()):
            for col in range(self.ADFGVXTable.columnCount()):
                item = self.ADFGVXTable.item(row, col)
                if item and item.text():
                    alphabet += item.text().upper()
        return alphabet

    def on_random_table_selected(self):
        self.is_manual_table = False
        self.ADFGVXTable.setEditTriggers(QTableWidget.NoEditTriggers)
        self.generate_random_adfgvx_table()

    def on_manual_table_selected(self):
        self.is_manual_table = True
        self.ADFGVXTable.setEditTriggers(
            QTableWidget.DoubleClicked | QTableWidget.SelectedClicked
        )
        size = self.ADFGVXTable.rowCount()
        for row in range(size):
            for col in range(size):
                self.ADFGVXTable.setItem(row, col, QTableWidgetItem(""))

    def on_encrypt_ADFGVX(self):
        try:
            plaintext = self.ADFGVXTextInput.toPlainText().strip()
            keyword = self.ADFGVXKeyInput.toPlainText().strip()
            if not plaintext:
                self.ADFGVXOutputBox.setPlainText("⚠ Please enter text.")
                return
            if not keyword:
                self.ADFGVXOutputBox.setPlainText("⚠ Please enter key.")
                return
            alphabet = self.get_alphabet_from_table()
            expected_size = 36 if self.language_ADFGVX == "6x6" else 25
            if len(alphabet) != expected_size:
                self.ADFGVXOutputBox.setPlainText(f"⚠ Table must contain {expected_size} characters")
                return
            ciphertext, table = adfgvx_encrypt(plaintext, keyword, alphabet, self.language_ADFGVX)
            self.ADFGVXOutputBox.setPlainText(f"Encrypted text:\n{ciphertext}")
            self.update_adfgvx_table(table)
        except Exception as e:
            self.ADFGVXOutputBox.setPlainText(f"⚠ Error during encryption: {e}")

    def on_decrypt_ADFGVX(self):
        try:
            ciphertext = self.ADFGVXTextInput.toPlainText().strip()
            keyword = self.ADFGVXKeyInput.toPlainText().strip()
            if not ciphertext:
                self.ADFGVXOutputBox.setPlainText("⚠ Please enter text to decrypt.")
                return
            if not keyword:
                self.ADFGVXOutputBox.setPlainText("⚠ Please enter key.")
                return
            alphabet = self.get_alphabet_from_table()
            expected_size = 36 if self.language_ADFGVX == "6x6" else 25
            if len(alphabet) != expected_size:
                self.ADFGVXOutputBox.setPlainText(f"⚠ Table must contain {expected_size} characters")
                return
            plaintext, table = adfgvx_decrypt(ciphertext, keyword, alphabet, self.language_ADFGVX)
            self.ADFGVXOutputBox.setPlainText(f"Decrypted text:\n{plaintext}")
            self.update_adfgvx_table(table)
        except Exception as e:
            self.ADFGVXOutputBox.setPlainText(f"⚠ Error during decryption: {e}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())