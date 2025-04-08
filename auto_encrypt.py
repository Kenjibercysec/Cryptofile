import os
import sys
import base64
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PySide6.QtWidgets import QApplication, QMessageBox

# Senha pré-definida - ALTERE AQUI A SENHA DESEJADA
PREDEFINED_PASSWORD = "12345678"

class AutoEncryptor:
    def __init__(self):
        self.salt = b'secure_explorer_salt'
        self.encrypted_files = set()
        
    def get_key(self, password):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def encrypt_file(self, file_path, key):
        try:
            fernet = Fernet(key)
            
            with open(file_path, 'rb') as file:
                original = file.read()
            
            encrypted = fernet.encrypt(original)
            
            encrypted_path = file_path + '.encrypted'
            with open(encrypted_path, 'wb') as file:
                file.write(encrypted)
            
            os.remove(file_path)
            self.encrypted_files.add(encrypted_path)
            return True
        except Exception as e:
            print(f"Erro ao criptografar {file_path}: {str(e)}")
            return False

    def encrypt_folder(self, folder_path, key):
        try:
            for root, _, files in os.walk(folder_path):
                for file in files:
                    if not file.endswith('.encrypted'):
                        file_path = os.path.join(root, file)
                        print(f"Criptografando: {file_path}")
                        self.encrypt_file(file_path, key)
        except Exception as e:
            print(f"Erro ao processar pasta {folder_path}: {str(e)}")

    def run(self):
        try:
            # Obter caminhos das pastas
            documents_path = os.path.join(os.path.expanduser("~"), "Documents")
            downloads_path = os.path.join(os.path.expanduser("~"), "Downloads")
            
            if not os.path.exists(documents_path) or not os.path.exists(downloads_path):
                QMessageBox.critical(None, "Erro", "Pastas Documentos e/ou Downloads não encontradas!")
                return

            # Gerar chave de criptografia
            key = self.get_key(PREDEFINED_PASSWORD)
            
            # Criptografar pastas
            print("Iniciando criptografia da pasta Documentos...")
            self.encrypt_folder(documents_path, key)
            
            print("Iniciando criptografia da pasta Downloads...")
            self.encrypt_folder(downloads_path, key)
            
            QMessageBox.information(None, "Concluído", "Criptografia concluída com sucesso!")
            
        except Exception as e:
            QMessageBox.critical(None, "Erro", f"Erro durante a criptografia: {str(e)}")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    encryptor = AutoEncryptor()
    encryptor.run()
    sys.exit(app.exec()) 