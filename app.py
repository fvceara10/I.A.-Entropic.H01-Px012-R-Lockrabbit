from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import pickle
from cryptography.fernet import Fernet
from Crypto.Cipher import AES, DES, Blowfish, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad
import numpy as np
import zipfile
import io
from flask import send_file

app = Flask(__name__)
CORS(app)  # Permitir requisições externas (ex.: Insomnia ou Ionic)

# Carregar o modelo treinado de IA


def load_model():
    with open("encryption_model.pkl", "rb") as file:
        return pickle.load(file)

# Extrair características do arquivo


def extract_features(file_path):
    with open(file_path, "rb") as file:
        file_data = file.read()
    return [len(file_data)]  # Retorna o tamanho do arquivo como característica

# Prever o algoritmo usando IA


def predict_algorithm(file_path):
    model = load_model()
    features = extract_features(file_path)
    algorithms = ["AES", "DES", "Blowfish", "Fernet", "RSA"]
    return algorithms[model.predict([features])[0]]

# Funções de criptografia


def encrypt_file(file_path, algorithm):
    with open(file_path, "rb") as file:
        data = file.read()

    if algorithm == "AES":
        key = os.urandom(16)
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return cipher.nonce + tag + ciphertext, key
    elif algorithm == "DES":
        key = os.urandom(8)
        cipher = DES.new(key, DES.MODE_CBC)
        return cipher.encrypt(pad(data, DES.block_size)), key
    elif algorithm == "Blowfish":
        key = os.urandom(16)
        cipher = Blowfish.new(key, Blowfish.MODE_ECB)
        return cipher.encrypt(pad(data, Blowfish.block_size)), key
    elif algorithm == "Fernet":
        key = Fernet.generate_key()
        cipher = Fernet(key)
        return cipher.encrypt(data), key
    elif algorithm == "RSA":
        key = RSA.generate(2048)
        public_key = key.publickey()
        cipher = PKCS1_OAEP.new(public_key)
        return cipher.encrypt(data), key.export_key()

# Rota para predição do algoritmo


@app.route('/predict', methods=['POST'])
def predict():

    # Verifica se o campo 'file' existe na requisição
    if 'file' not in request.files:
        return jsonify({"error": "O campo 'file' é obrigatório"}), 400

    # Recebe o arquivo enviado
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "Nenhum arquivo foi enviado"}), 400

    # Salva o arquivo original na pasta `uploads`
    file_path = os.path.join("uploads", file.filename)
    file.save(file_path)

    # Faz a predição do algoritmo baseado no arquivo
    algorithm = predict_algorithm(file_path)

    # Criptografar o arquivo com a chave correta
    # Criptografa com a chave gerada
    encrypted_data, key = encrypt_file(file_path, algorithm)

    # Salva o arquivo criptografado na pasta `uploads`
    encrypted_file_name = file.filename + ".encrypted"
    encrypted_file_path = os.path.join("uploads", encrypted_file_name)
    with open(encrypted_file_path, "wb") as encrypted_file:
        encrypted_file.write(encrypted_data)

    # Salva a chave na pasta `downloads` (para uso futuro na descriptografia)
    key_file_name = file.filename + "_key.txt"
    key_file_path = os.path.join("downloads", key_file_name)
    with open(key_file_path, "wb") as key_file:
        key_file.write(key)

    # Cria um arquivo ZIP contendo o arquivo original, o criptografado e a chave
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        zip_file.write(file_path, os.path.basename(file_path)
                       )          # Adiciona o arquivo original
        # Adiciona o arquivo criptografado
        zip_file.write(encrypted_file_path, encrypted_file_name)
        # Adiciona a chave de descriptografia
        zip_file.write(key_file_path, key_file_name)

    zip_buffer.seek(0)

    # Envia o arquivo ZIP como resposta
    return send_file(zip_buffer, as_attachment=True, download_name="prediction_results.zip")


# Rota para criptografia do arquivo
@app.route('/encrypt', methods=['POST'])
def encrypt():
    # Verifica se o campo 'file' está presente
    if 'file' not in request.files or request.files['file'].filename == '':
        return jsonify({"error": "Nenhum arquivo foi enviado ou o campo 'file' está ausente"}), 400

    # Receber o arquivo enviado na requisição
    file = request.files['file']
    file_path = os.path.join("uploads", file.filename)
    file.save(file_path)

    # Recebe o algoritmo de criptografia (padrão: AES)
    algorithm = request.form.get('algorithm', 'AES')

    # Criptografar o arquivo
    encrypted_data, key = encrypt_file(file_path, algorithm)

    # Salvar o arquivo criptografado na pasta `uploads`
    encrypted_file_name = file.filename + ".encrypted"
    encrypted_file_path = os.path.join("uploads", encrypted_file_name)
    with open(encrypted_file_path, "wb") as encrypted_file:
        encrypted_file.write(encrypted_data)

    # Salvar a chave na pasta `downloads`
    key_file_name = file.filename + "_key.txt"
    key_file_path = os.path.join("downloads", key_file_name)
    with open(key_file_path, "wb") as key_file:
        key_file.write(key)

    # Criar um arquivo ZIP contendo o arquivo criptografado, descriptografado e a chave
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        # Adiciona o arquivo criptografado
        zip_file.write(encrypted_file_path, encrypted_file_name)
        # Adiciona o arquivo da chave
        zip_file.write(key_file_path, key_file_name)

    zip_buffer.seek(0)

    # Retornar o ZIP como resposta
    return send_file(zip_buffer, as_attachment=True, download_name="encrypted_files.zip")


@app.route('/decrypt', methods=['POST'])
def decrypt():
    # Verifica se o arquivo criptografado e a chave foram enviados
    if 'encrypted_file' not in request.files or request.files['encrypted_file'].filename == '':
        return jsonify({"error": "Nenhum arquivo criptografado foi enviado ou o campo 'encrypted_file' está ausente"}), 400
    if 'key_file' not in request.files or request.files['key_file'].filename == '':
        return jsonify({"error": "Nenhuma chave foi enviada ou o campo 'key_file' está ausente"}), 400

    # Receber os arquivos enviados na requisição
    encrypted_file = request.files['encrypted_file']
    key_file = request.files['key_file']

    # Salvar os arquivos localmente
    encrypted_file_path = os.path.join("uploads", encrypted_file.filename)
    key_file_path = os.path.join("uploads", key_file.filename)
    encrypted_file.save(encrypted_file_path)
    key_file.save(key_file_path)

    # Carregar o conteúdo do arquivo criptografado e da chave
    with open(encrypted_file_path, "rb") as enc_file:
        encrypted_data = enc_file.read()
    with open(key_file_path, "rb") as key_file:
        key = key_file.read()

    # Detectar o algoritmo a partir do tamanho da chave (ou outras propriedades conhecidas)
    decrypted_data = None
    if len(key) == 16:  # AES
        cipher = AES.new(key, AES.MODE_EAX, nonce=encrypted_data[:16])
        decrypted_data = cipher.decrypt(encrypted_data[32:])
    elif len(key) == 8:  # DES
        cipher = DES.new(key, DES.MODE_CBC)
        decrypted_data = cipher.decrypt(encrypted_data)
    elif len(key) == 16 and len(encrypted_data) % Blowfish.block_size == 0:  # Blowfish
        cipher = Blowfish.new(key, Blowfish.MODE_ECB)
        decrypted_data = cipher.decrypt(encrypted_data)
    elif len(key) > 100:  # RSA
        rsa_key = RSA.import_key(key)
        cipher = PKCS1_OAEP.new(rsa_key)
        decrypted_data = cipher.decrypt(encrypted_data)
    else:
        return jsonify({"error": "Algoritmo desconhecido ou chave inválida"}), 400

    # Preservar a extensão original do arquivo
    original_extension = os.path.splitext(
        encrypted_file.filename.replace(".encrypted", ""))[1]
    decrypted_file_name = encrypted_file.filename.replace(".encrypted", "")
    decrypted_file_path = os.path.join("uploads", decrypted_file_name)

    # Salvar o arquivo descriptografado com a extensão original
    with open(decrypted_file_path, "wb") as dec_file:
        dec_file.write(decrypted_data)

    # Verificar se o arquivo foi descriptografado corretamente
    if not os.path.exists(decrypted_file_path):
        return jsonify({"error": "Falha ao descriptografar o arquivo"}), 500

    # Retornar o arquivo descriptografado para o cliente
    return send_file(decrypted_file_path, as_attachment=True, download_name=decrypted_file_name)


# Página inicial
@app.route('/')
def home():
    return "Flask está rodando e pronto para processar requisições!"


# Executar o servidor
if __name__ == '__main__':
    # Certifique-se de que as pastas existam
    os.makedirs("uploads", exist_ok=True)
    os.makedirs("downloads", exist_ok=True)
    app.run(debug=True, host='0.0.0.0', port=5000)
