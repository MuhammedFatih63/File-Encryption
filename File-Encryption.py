import sys
import base64
import hashlib
import threading
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QFileDialog, QLabel, QComboBox, QLineEdit, QMessageBox
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

class EncryptionApp(QWidget):
    def __init__(self):
        super().__init__()

        self.initUI()

    def initUI(self):
        self.setWindowTitle("🔒 Linux Dosya Şifreleme Aracı")
        self.setGeometry(100, 100, 400, 250)

        layout = QVBoxLayout()

        # 📂 Dosya Seçme Butonu
        self.selectFileButton = QPushButton("📂 Dosya Seç")
        self.selectFileButton.clicked.connect(self.select_file)
        layout.addWidget(self.selectFileButton)

        self.fileLabel = QLabel("Seçilen Dosya: Yok")
        layout.addWidget(self.fileLabel)

        # 🔑 Şifreleme Seçenekleri
        self.encryptionComboBox = QComboBox()
        self.encryptionComboBox.addItems(["Base64 (Zayıf)", "XOR (Orta)", "AES-256 (Güçlü)", "RSA-2048 (Çok Güçlü)"])
        layout.addWidget(self.encryptionComboBox)

        # 🔑 Şifreleme Anahtarı
        self.keyInput = QLineEdit()
        self.keyInput.setPlaceholderText("Şifreleme için anahtar girin...")
        layout.addWidget(self.keyInput)

        # 🔒 Şifreleme Butonu
        self.encryptButton = QPushButton("🔒 Dosyayı Şifrele")
        self.encryptButton.clicked.connect(self.encrypt_file)
        layout.addWidget(self.encryptButton)

        # 🔓 Deşifreleme Butonu
        self.decryptButton = QPushButton("🔓 Dosyayı Deşifre Et")
        self.decryptButton.clicked.connect(self.decrypt_file)
        layout.addWidget(self.decryptButton)

        self.setLayout(layout)

    def select_file(self):
        file, _ = QFileDialog.getOpenFileName(self, "Dosya Seç", "", "Tüm Dosyalar (*)")
        if file:
            self.file_path = file
            self.fileLabel.setText(f"Seçilen Dosya: {file}")

    def encrypt_file(self):
        if not hasattr(self, "file_path"):
            QMessageBox.warning(self, "Hata", "Önce bir dosya seçmelisiniz!")
            return

        key = self.keyInput.text()
        if not key:
            QMessageBox.warning(self, "Hata", "Lütfen bir anahtar girin!")
            return

        method = self.encryptionComboBox.currentText()
        threading.Thread(target=self.process_encryption, args=(method, key), daemon=True).start()

    def decrypt_file(self):
        if not hasattr(self, "file_path"):
            QMessageBox.warning(self, "Hata", "Önce bir dosya seçmelisiniz!")
            return

        key = self.keyInput.text()
        if not key:
            QMessageBox.warning(self, "Hata", "Lütfen bir anahtar girin!")
            return

        method = self.encryptionComboBox.currentText()
        threading.Thread(target=self.process_decryption, args=(method, key), daemon=True).start()

    def process_encryption(self, method, key):
        with open(self.file_path, "rb") as f:
            data = f.read()

        if "Base64" in method:
            encrypted_data = base64.b64encode(data)
        elif "XOR" in method:
            encrypted_data = bytes([b ^ int(key) % 256 for b in data])
        elif "AES-256" in method:
            encrypted_data = self.aes_encrypt(data, key)
        elif "RSA-2048" in method:
            private_key, public_key = self.generate_rsa_keys()
            encrypted_data = self.rsa_encrypt(data, public_key)
            with open("private.pem", "wb") as f:
                f.write(private_key)
        else:
            return

        with open(f"{self.file_path}.enc", "wb") as f:
            f.write(encrypted_data)

        QMessageBox.information(self, "Başarılı", f"Dosya başarıyla şifrelendi: {self.file_path}.enc")

    def process_decryption(self, method, key):
        with open(self.file_path, "rb") as f:
            data = f.read()

        if "Base64" in method:
            decrypted_data = base64.b64decode(data)
        elif "XOR" in method:
            decrypted_data = bytes([b ^ int(key) % 256 for b in data])
        elif "AES-256" in method:
            decrypted_data = self.aes_decrypt(data, key)
        elif "RSA-2048" in method:
            with open("private.pem", "rb") as f:
                private_key = f.read()
            decrypted_data = self.rsa_decrypt(data, private_key)
        else:
            return

        with open(f"{self.file_path}.dec", "wb") as f:
            f.write(decrypted_data)

        QMessageBox.information(self, "Başarılı", f"Dosya başarıyla çözüldü: {self.file_path}.dec")

    def aes_encrypt(self, data, key):
        key = hashlib.sha256(key.encode()).digest()
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return cipher.nonce + tag + ciphertext

    def aes_decrypt(self, data, key):
        key = hashlib.sha256(key.encode()).digest()
        nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)

    def generate_rsa_keys(self):
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key, public_key

    def rsa_encrypt(self, data, public_key):
        recipient_key = RSA.import_key(public_key)
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        return cipher_rsa.encrypt(data)

    def rsa_decrypt(self, data, private_key):
        key = RSA.import_key(private_key)
        cipher_rsa = PKCS1_OAEP.new(key)
        return cipher_rsa.decrypt(data)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = EncryptionApp()
    window.show()
    sys.exit(app.exec())
