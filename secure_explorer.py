import os
import sys
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
from PySide6.QtWidgets import (QApplication, QMainWindow, QFileDialog, QMessageBox,
                           QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
                           QLineEdit, QTreeView, QWidget, QDialog, QProgressBar)
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFileSystemModel
import argon2
import cryptography

print(f"Cryptography version: {cryptography.__version__}")

class PasswordDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Enter Password")
        self.setModal(True)
        
        layout = QVBoxLayout()
        
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(QLabel("Password:"))
        layout.addWidget(self.password_input)
        
        self.confirm_button = QPushButton("Confirm")
        self.confirm_button.clicked.connect(self.accept)
        layout.addWidget(self.confirm_button)
        
        self.setLayout(layout)
    
    def get_password(self):
        return self.password_input.text()

class SecureExplorer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure File Explorer")
        self.setGeometry(100, 100, 800, 600)
        
        # Encryption configuration
        self.salt = b'secure_explorer_salt'  # In production, use a unique salt per file
        self.encrypted_files = set()
        self.predefined_password = "12345678"  # Senha pré-definida do AutoEncryptor
        
        # Main interface
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout()
        
        # Navigation area
        self.model = QFileSystemModel()
        self.model.setRootPath("")
        
        self.tree = QTreeView()
        self.tree.setModel(self.model)
        self.tree.setRootIndex(self.model.index(str(Path.home())))
        self.tree.setSelectionMode(QTreeView.SelectionMode.ExtendedSelection)  # Enable multiple selection
        self.tree.doubleClicked.connect(self.handle_file_click)
        layout.addWidget(self.tree)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Action buttons
        button_layout = QHBoxLayout()
        
        self.encrypt_button = QPushButton("Encrypt File")
        self.encrypt_button.clicked.connect(self.encrypt_file)
        button_layout.addWidget(self.encrypt_button)
        
        self.decrypt_button = QPushButton("Decrypt Selected Files")
        self.decrypt_button.clicked.connect(self.decrypt_selected_files)
        button_layout.addWidget(self.decrypt_button)
        
        layout.addLayout(button_layout)
        main_widget.setLayout(layout)
    
    def get_key(self, password):
        print(f"Gerando chave para senha: {password}")
        print(f"Salt usado: {self.salt}")
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        
        key_bytes = kdf.derive(password.encode())
        print(f"Bytes da chave antes do base64: {key_bytes}")
        print(f"Bytes da chave antes do base64 (hex): {key_bytes.hex()}")
        
        key = base64.urlsafe_b64encode(key_bytes)
        print(f"Chave final: {key}")
        print(f"Chave final (decoded): {base64.urlsafe_b64decode(key).hex()}")
        
        return key
    
    def encrypt_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select file to encrypt")
        if not file_path:
            return
        
        dialog = PasswordDialog(self)
        if dialog.exec() == QDialog.Accepted:
            password = dialog.get_password()
            if not password:
                QMessageBox.warning(self, "Error", "Password cannot be empty")
                return
            
            try:
                key = self.get_key(password)
                fernet = Fernet(key)
                
                with open(file_path, 'rb') as file:
                    original = file.read()
                
                encrypted = fernet.encrypt(original)
                
                encrypted_path = file_path + '.encrypted'
                with open(encrypted_path, 'wb') as file:
                    file.write(encrypted)
                
                os.remove(file_path)
                self.encrypted_files.add(encrypted_path)
                QMessageBox.information(self, "Success", "File encrypted successfully!")
                
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Error encrypting file: {str(e)}")
    
    def decrypt_file(self, file_path, key):
        try:
            print(f"\nTentando descriptografar: {file_path}")
            print(f"Tamanho da chave: {len(key)}")
            print(f"Chave em hex: {base64.urlsafe_b64decode(key).hex()}")
            
            # Criar objeto Fernet com a chave
            fernet = Fernet(key)
            
            # Ler o arquivo criptografado
            with open(file_path, 'rb') as file:
                encrypted = file.read()
            
            print(f"Tamanho dos dados criptografados: {len(encrypted)}")
            print(f"Primeiros 100 bytes dos dados criptografados: {encrypted[:100]}")
            
            # Tentar descriptografar com TTL desabilitado
            decrypted = fernet.decrypt(encrypted, ttl=None)
            print(f"Decriptação bem-sucedida! Tamanho dos dados descriptografados: {len(decrypted)}")
            
            # Salvar o arquivo descriptografado
            decrypted_path = file_path.replace('.encrypted', '')
            with open(decrypted_path, 'wb') as file:
                file.write(decrypted)
            
            # Remover o arquivo criptografado
            os.remove(file_path)
            self.encrypted_files.discard(file_path)
            print(f"Arquivo descriptografado com sucesso: {decrypted_path}")
            return True
            
        except cryptography.fernet.InvalidToken as e:
            print(f"Erro de token inválido ao descriptografar {file_path}:")
            print(f"Isso geralmente significa que a chave está incorreta ou os dados estão corrompidos")
            print(f"Detalhes do erro: {str(e)}")
            return False
            
        except Exception as e:
            print(f"Erro ao descriptografar {file_path}:")
            print(f"Tipo do erro: {type(e)}")
            print(f"Mensagem de erro: {str(e)}")
            return False
    
    def decrypt_selected_files(self):
        indexes = self.tree.selectedIndexes()
        if not indexes:
            QMessageBox.warning(self, "Warning", "Please select files to decrypt")
            return
        
        # Verificar se todos os arquivos selecionados são arquivos criptografados
        encrypted_files = []
        for index in indexes:
            file_path = self.model.filePath(index)
            if file_path.endswith('.encrypted'):
                encrypted_files.append(file_path)
            else:
                QMessageBox.warning(self, "Warning", f"File {file_path} is not encrypted")
                return
        
        if not encrypted_files:
            QMessageBox.warning(self, "Warning", "No encrypted files selected")
            return
        
        # Usar senha pré-definida
        password = self.predefined_password
        print(f"Usando senha pré-definida: {password}")
        key = self.get_key(password)
        print(f"Chave gerada: {key}")
        
        # Criar barra de progresso
        progress = QProgressBar()
        progress.setMaximum(len(encrypted_files))
        progress.setValue(0)
        progress.setFormat("Decrypting files: %p%")
        
        # Adicionar barra de progresso à janela
        self.statusBar().addWidget(progress)
        
        # Descriptografar arquivos
        success_count = 0
        for i, file_path in enumerate(encrypted_files):
            print(f"Processando arquivo {i+1}/{len(encrypted_files)}: {file_path}")
            if self.decrypt_file(file_path, key):
                success_count += 1
            progress.setValue(i + 1)
            QApplication.processEvents()
        
        # Remover barra de progresso
        self.statusBar().removeWidget(progress)
        
        # Mostrar resultado
        if success_count == len(encrypted_files):
            QMessageBox.information(self, "Success", f"Successfully decrypted {success_count} files")
        else:
            QMessageBox.warning(self, "Partial Success", 
                              f"Decrypted {success_count} out of {len(encrypted_files)} files")
    
    def handle_file_click(self, index):
        file_path = self.model.filePath(index)
        if file_path in self.encrypted_files:
            self.decrypt_selected_files()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = SecureExplorer()
    window.show()
    sys.exit(app.exec()) 