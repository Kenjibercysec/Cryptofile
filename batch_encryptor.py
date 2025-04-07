import os
import sys
import base64
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PySide6.QtWidgets import (QApplication, QMainWindow, QPushButton, QVBoxLayout,
                             QLabel, QLineEdit, QFileDialog, QMessageBox, QWidget,
                             QProgressBar, QTextEdit)
from PySide6.QtCore import Qt, QThread, Signal

class EncryptionWorker(QThread):
    progress = Signal(int)
    status = Signal(str)
    finished = Signal()

    def __init__(self, password, target_paths, parent=None):
        super().__init__(parent)
        self.password = password
        self.target_paths = target_paths
        self.salt = b'secure_explorer_salt'
        self.encrypted_files = set()
        self.total_files = 0
        self.processed_files = 0

    def get_key(self, password):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def count_files(self, path):
        count = 0
        for root, _, files in os.walk(path):
            count += len(files)
        return count

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
            self.status.emit(f"Erro ao criptografar {file_path}: {str(e)}")
            return False

    def run(self):
        try:
            # Contar total de arquivos
            self.total_files = 0
            for path in self.target_paths:
                self.total_files += self.count_files(path)
            
            if self.total_files == 0:
                self.status.emit("Nenhum arquivo encontrado para criptografar.")
                self.finished.emit()
                return

            key = self.get_key(self.password)
            
            for path in self.target_paths:
                for root, _, files in os.walk(path):
                    for file in files:
                        if not file.endswith('.encrypted'):
                            file_path = os.path.join(root, file)
                            self.status.emit(f"Criptografando: {file_path}")
                            self.encrypt_file(file_path, key)
                            self.processed_files += 1
                            progress = int((self.processed_files / self.total_files) * 100)
                            self.progress.emit(progress)
            
            self.status.emit("Criptografia concluída com sucesso!")
            self.finished.emit()
        except Exception as e:
            self.status.emit(f"Erro durante a criptografia: {str(e)}")
            self.finished.emit()

class BatchEncryptor(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Criptografador em Lote")
        self.setGeometry(100, 100, 800, 600)
        
        # Widget principal
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout()
        
        # Senha
        password_layout = QVBoxLayout()
        password_layout.addWidget(QLabel("Senha de Criptografia:"))
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        password_layout.addWidget(self.password_input)
        layout.addLayout(password_layout)
        
        # Botões
        button_layout = QHBoxLayout()
        
        self.select_button = QPushButton("Selecionar Pastas")
        self.select_button.clicked.connect(self.select_folders)
        button_layout.addWidget(self.select_button)
        
        self.encrypt_button = QPushButton("Iniciar Criptografia")
        self.encrypt_button.clicked.connect(self.start_encryption)
        button_layout.addWidget(self.encrypt_button)
        
        layout.addLayout(button_layout)
        
        # Barra de progresso
        self.progress_bar = QProgressBar()
        layout.addWidget(self.progress_bar)
        
        # Log
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        layout.addWidget(self.log_text)
        
        main_widget.setLayout(layout)
        
        self.target_paths = []
        self.worker = None

    def select_folders(self):
        folders = QFileDialog.getExistingDirectory(
            self,
            "Selecione as pastas para criptografar",
            "",
            QFileDialog.ShowDirsOnly
        )
        if folders:
            self.target_paths.append(folders)
            self.log_text.append(f"Pasta selecionada: {folders}")

    def start_encryption(self):
        if not self.target_paths:
            QMessageBox.warning(self, "Erro", "Selecione pelo menos uma pasta para criptografar.")
            return
        
        password = self.password_input.text()
        if not password:
            QMessageBox.warning(self, "Erro", "Digite uma senha para criptografia.")
            return
        
        reply = QMessageBox.question(
            self,
            "Confirmar Criptografia",
            "Tem certeza que deseja criptografar os arquivos selecionados? Esta ação não pode ser desfeita sem a senha correta.",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.worker = EncryptionWorker(password, self.target_paths)
            self.worker.progress.connect(self.update_progress)
            self.worker.status.connect(self.update_status)
            self.worker.finished.connect(self.encryption_finished)
            self.worker.start()
            
            self.encrypt_button.setEnabled(False)
            self.select_button.setEnabled(False)
            self.password_input.setEnabled(False)

    def update_progress(self, value):
        self.progress_bar.setValue(value)

    def update_status(self, message):
        self.log_text.append(message)

    def encryption_finished(self):
        self.encrypt_button.setEnabled(True)
        self.select_button.setEnabled(True)
        self.password_input.setEnabled(True)
        QMessageBox.information(self, "Concluído", "Processo de criptografia finalizado!")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = BatchEncryptor()
    window.show()
    sys.exit(app.exec()) 