import os
import pickle
import numpy as np
from Crypto.Cipher import AES, DES, Blowfish, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad  # Importação correta para padding
from cryptography.fernet import Fernet
from sklearn.ensemble import RandomForestClassifier

# 🔹 Função para extrair características do arquivo
# Essa função pega o caminho do arquivo, abre o arquivo como binário, lê o conteúdo e retorna seu tamanho.


def extract_features(file_path):
    with open(file_path, "rb") as file:
        file_data = file.read()
    return [len(file_data)]  # Característica: tamanho do arquivo

# 🔹 Função para treinar o modelo de IA para prever o algoritmo
# Essa função treina um modelo de IA para classificar o arquivo baseado no seu tamanho.
# A IA será treinada para escolher entre os algoritmos de criptografia: AES, DES, Blowfish, Fernet, e RSA.


def train_model():
    # Tamanhos de arquivos fictícios para treinar o modelo
    # Exemplos de tamanhos
    X = np.array([[500], [1000], [2000], [3000], [5000]])
    # Mapeia AES (0), DES (1), Blowfish (2), Fernet (3), RSA (4)
    y = np.array([0, 1, 2, 3, 4])

    # Usamos o Random Forest para classificar os tamanhos dos arquivos
    model = RandomForestClassifier()
    model.fit(X, y)  # Treinamento do modelo

    with open("encryption_model.pkl", "wb") as file:
        pickle.dump(model, file)  # Salvando o modelo treinado em um arquivo

# 🔹 Função para fazer predição do algoritmo usando IA
# Essa função carrega o modelo treinado e tenta prever qual algoritmo usar baseado no tamanho do arquivo.


def predict_algorithm(file_path):
    with open("encryption_model.pkl", "rb") as file:
        model = pickle.load(file)  # Carrega o modelo treinado
    features = extract_features(file_path)  # Extrai características do arquivo
    algorithms = ["AES", "DES", "Blowfish",
                  "Fernet", "RSA"]  # Lista de algoritmos
    # Preve a classe e retorna o nome do algoritmo
    return algorithms[model.predict([features])[0]]

# 🔹 Função para escolher algoritmo baseado na extensão do arquivo
# Essa função determina qual algoritmo de criptografia deve ser usado baseado na extensão do arquivo.


def escolher_algoritmo(file_path):
    # Mapeamento de tipos de arquivos para algoritmos de criptografia
    tipos = {
        "texto": "AES", "imagem": "Blowfish", "vídeo": "Blowfish",
        "áudio": "Fernet", "documento": "AES", "executável": "RSA",
        "compactado": "AES"
    }

    # Mapeamento de extensões para tipos de arquivo
    ext_map = {
        ".txt": "texto", ".csv": "texto", ".json": "texto", ".xml": "texto",
        ".jpg": "imagem", ".png": "imagem", ".bmp": "imagem", ".gif": "imagem",
        ".mp4": "vídeo", ".avi": "vídeo", ".mkv": "vídeo",
        ".mp3": "áudio", ".wav": "áudio", ".flac": "áudio",
        ".pdf": "documento", ".docx": "documento", ".xlsx": "documento",
        ".exe": "executável", ".dll": "executável",
        ".zip": "compactado", ".rar": "compactado", ".gz": "compactado"
    }
    _, ext = os.path.splitext(file_path)  # Pega a extensão do arquivo
    # Retorna o algoritmo baseado na extensão
    return tipos.get(ext_map.get(ext, "texto"), "AES")

# 🔹 Funções de criptografia com padding correto
# Essas funções realizam a criptografia de dados usando os algoritmos AES, DES, Blowfish, Fernet e RSA.


def encrypt_aes(data):
    key = os.urandom(16)  # Gera uma chave aleatória de 16 bytes
    # Cria um objeto de criptografia AES no modo EAX
    cipher = AES.new(key, AES.MODE_EAX)
    # Criptografa e gera a tag de integridade
    ciphertext, tag = cipher.encrypt_and_digest(data)
    # Retorna o nonce, tag e dados criptografados junto com a chave
    return cipher.nonce + tag + ciphertext, key


def encrypt_des(data):
    key = os.urandom(8)  # Gera uma chave aleatória de 8 bytes
    # Cria um objeto de criptografia DES no modo CBC
    cipher = DES.new(key, DES.MODE_CBC)
    # Criptografa e retorna a chave
    return cipher.encrypt(pad(data, DES.block_size)), key


def encrypt_blowfish(data):
    key = os.urandom(16)  # Gera uma chave aleatória de 16 bytes
    # Cria um objeto de criptografia Blowfish no modo ECB
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    # Criptografa e retorna a chave
    return cipher.encrypt(pad(data, Blowfish.block_size)), key


def encrypt_fernet(data):
    key = Fernet.generate_key()  # Gera uma chave aleatória para o Fernet
    cipher = Fernet(key)  # Cria o objeto de criptografia
    return cipher.encrypt(data), key  # Criptografa e retorna a chave


def encrypt_rsa(data):
    key = RSA.generate(2048)  # Gera uma chave RSA de 2048 bits
    public_key = key.publickey()  # Obtém a chave pública
    # Cria o objeto de criptografia RSA com PKCS1_OAEP
    cipher = PKCS1_OAEP.new(public_key)
    # Criptografa e retorna a chave pública exportada
    return cipher.encrypt(data), key.export_key()

# 🔹 Função para salvar a chave como um arquivo de texto para download
# Essa função cria um arquivo contendo a chave de criptografia para ser baixada posteriormente


def save_key_for_download(key, encrypted_file_name):
    # Cria a pasta "downloads" se não existir
    os.makedirs("downloads", exist_ok=True)
    # Caminho para o arquivo de chave
    key_file_path = os.path.join("downloads", f"{encrypted_file_name}_key.txt")
    with open(key_file_path, "wb") as key_file:
        key_file.write(key)  # Escreve a chave no arquivo
    return key_file_path  # Retorna o caminho do arquivo da chave

# 🔹 Função principal para criptografar o arquivo e fornecer a chave para download
# Essa função usa um algoritmo de criptografia (especificado ou escolhido automaticamente) e salva tanto o arquivo criptografado quanto a chave.


def encrypt_file_and_provide_key(file_path):
    with open(file_path, "rb") as file:
        data = file.read()  # Lê o conteúdo do arquivo

    # Escolhe o algoritmo de criptografia a ser usado
    algorithm = "AES"  # Aqui você pode substituir por qualquer algoritmo desejado ou usar o modelo de IA para prever
    if algorithm == "AES":
        encrypted_data, key = encrypt_aes(data)
    elif algorithm == "DES":
        encrypted_data, key = encrypt_des(data)
    elif algorithm == "Blowfish":
        encrypted_data, key = encrypt_blowfish(data)
    elif algorithm == "Fernet":
        encrypted_data, key = encrypt_fernet(data)
    elif algorithm == "RSA":
        encrypted_data, key = encrypt_rsa(data)

    # Gera o nome do arquivo criptografado
    encrypted_file_name = file_path + ".encrypted"

    with open(encrypted_file_name, "wb") as encrypted_file:
        encrypted_file.write(encrypted_data)  # Salva o arquivo criptografado

    # Salva a chave de criptografia para download
    key_file_path = save_key_for_download(key, encrypted_file_name)

    # Retorna os caminhos do arquivo criptografado e da chave
    return encrypted_file_name, key_file_path


# 🔹 Exemplo de uso
file_path = "meuarquivo.txt"  # Caminho do arquivo original
encrypted_file_name, key_file_path = encrypt_file_and_provide_key(file_path)

print(f"Arquivo criptografado: {encrypted_file_name}")
print(f"Link para download da chave: {key_file_path}")

train_model()
print("Modelo treinado e salvo como 'encryption_model.pkl'")
