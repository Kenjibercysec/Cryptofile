# Explorador de Arquivos Seguro

Um explorador de arquivos com criptografia avançada e proteção por senha, compatível com Windows e Linux.

## Características

- Interface gráfica moderna e intuitiva
- Criptografia forte usando Fernet (AES-128-CBC)
- Proteção por senha com PBKDF2HMAC
- Compatível com Windows e Linux
- Navegação de arquivos integrada
- Criptografia e descriptografia de arquivos individuais

## Requisitos

- Python 3.8 ou superior
- Bibliotecas listadas em `requirements.txt`

## Instalação

1. Clone este repositório ou baixe os arquivos
2. Instale as dependências:
```bash
pip install -r requirements.txt
```

## Uso

Execute o programa:
```bash
python secure_explorer.py
```

### Como usar

1. **Criptografar um arquivo**:
   - Clique no botão "Criptografar Arquivo"
   - Selecione o arquivo desejado
   - Digite uma senha forte
   - O arquivo será criptografado e o original será removido

2. **Descriptografar um arquivo**:
   - Clique no botão "Descriptografar Arquivo"
   - Selecione o arquivo criptografado
   - Digite a senha correta
   - O arquivo será descriptografado e o arquivo criptografado será removido

## Segurança

- Utiliza criptografia Fernet (AES-128-CBC)
- Implementa PBKDF2HMAC para derivação de chaves
- Senhas são processadas de forma segura
- Arquivos originais são removidos após criptografia
- Arquivos criptografados são removidos após descriptografia

## Aviso

Este software é fornecido "como está", sem garantias. O desenvolvedor não se responsabiliza por qualquer perda de dados ou problemas decorrentes do uso deste software. 