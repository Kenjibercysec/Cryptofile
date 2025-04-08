import os
import sys
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
from PySide6.QtWidgets import (QApplication, QMainWindow, QFileDialog, QMessageBox,
                           QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
                           QLineEdit, QTreeView, QWidget, QDialog)
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFileSystemModel
import argon2

class PasswordDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Digite a senha")
        self.setModal(True)
        
        layout = QVBoxLayout()
        
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(QLabel("Senha:"))
        layout.addWidget(self.password_input)
        
        self.confirm_button = QPushButton("Confirmar")
        self.confirm_button.clicked.connect(self.accept)
        layout.addWidget(self.confirm_button)
        
        self.setLayout(layout)
    
    def get_password(self):
        return self.password_input.text()

class SecureExplorer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Explorador de Arquivos Seguro")
        self.setGeometry(100, 100, 800, 600)
        
        # Configuração da criptografia
        self.salt = b'secure_explorer_salt'  # Em produção, use um salt único por arquivo
        self.encrypted_files = set()
        
        # Interface principal
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout()
        
        # Área de navegação
        self.model = QFileSystemModel()
        self.model.setRootPath("")
        
        self.tree = QTreeView()
        self.tree.setModel(self.model)
        self.tree.setRootIndex(self.model.index(str(Path.home())))
        self.tree.doubleClicked.connect(self.handle_file_click)
        layout.addWidget(self.tree)
        
        # Botões de ação
        button_layout = QHBoxLayout()
        
        self.encrypt_button = QPushButton("Criptografar Arquivo")
        self.encrypt_button.clicked.connect(self.encrypt_file)
        button_layout.addWidget(self.encrypt_button)
        
        self.decrypt_button = QPushButton("Descriptografar Arquivo")
        self.decrypt_button.clicked.connect(self.decrypt_file)
        button_layout.addWidget(self.decrypt_button)
        
        layout.addLayout(button_layout)
        main_widget.setLayout(layout)
    
    def get_key(self, password):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def encrypt_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Selecione o arquivo para criptografar")
        if not file_path:
            return
        
        dialog = PasswordDialog(self)
        if dialog.exec() == QDialog.Accepted:
            password = dialog.get_password()
            if not password:
                QMessageBox.warning(self, "Erro", "A senha não pode estar vazia")
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
                QMessageBox.information(self, "Sucesso", "Arquivo criptografado com sucesso!")
                
            except Exception as e:
                QMessageBox.critical(self, "Erro", f"Erro ao criptografar arquivo: {str(e)}")
    
    def decrypt_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Selecione o arquivo para descriptografar")
        if not file_path:
            return
        
        dialog = PasswordDialog(self)
        if dialog.exec() == QDialog.Accepted:
            password = dialog.get_password()
            if not password:
                QMessageBox.warning(self, "Erro", "A senha não pode estar vazia")
                return
            
            try:
                key = self.get_key(password)
                fernet = Fernet(key)
                
                with open(file_path, 'rb') as file:
                    encrypted = file.read()
                
                decrypted = fernet.decrypt(encrypted)
                
                decrypted_path = file_path.replace('.encrypted', '')
                with open(decrypted_path, 'wb') as file:
                    file.write(decrypted)
                
                os.remove(file_path)
                self.encrypted_files.discard(file_path)
                QMessageBox.information(self, "Sucesso", "Arquivo descriptografado com sucesso!")
                
            except Exception as e:
                QMessageBox.critical(self, "Erro", f"Erro ao descriptografar arquivo: {str(e)}")
    
    def handle_file_click(self, index):
        file_path = self.model.filePath(index)
        if file_path in self.encrypted_files:
            self.decrypt_file()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = SecureExplorer()
    window.show()
    sys.exit(app.exec()) 