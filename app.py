# Importa os módulos necessários do Flask
from flask import Flask, request, jsonify
# Importa o CORS para permitir requisições de origens diferentes (do HTML para o Flask)
from flask_cors import CORS
# Importa ferramentas de segurança para hashing de senhas
from werkzeug.security import generate_password_hash, check_password_hash

# Cria uma instância do aplicativo Flask
app = Flask(__name__)
# Habilita o CORS para todas as rotas.
# Isso é importante para que o navegador permita que seu arquivo HTML (executado localmente)
# se comunique com o servidor Flask. Em produção, você restringiria isso a domínios específicos.
CORS(app)

# Dicionário simples para armazenar usuários.
# Em um sistema real, isso seria um banco de dados (ex: SQLite, PostgreSQL, MongoDB).
# A chave é o nome de usuário e o valor é o hash da senha.
users_db = {}

# Rota para o cadastro de novos usuários (método POST)
@app.route('/register', methods=['POST'])
def register():
    # Obtém os dados JSON enviados na requisição
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Verifica se nome de usuário e senha foram fornecidos
    if not username or not password:
        return jsonify({"message": "Nome de usuário e senha são obrigatórios"}), 400

    # Verifica se o nome de usuário já existe no nosso "banco de dados"
    if username in users_db:
        return jsonify({"message": "Nome de usuário já existe"}), 409 # 409 Conflict

    # Gera um hash da senha. ESSENCIAL para segurança!
    # Nunca armazene senhas em texto simples.
    hashed_password = generate_password_hash(password)
    users_db[username] = hashed_password

    # Retorna uma resposta de sucesso
    return jsonify({"message": "Usuário registrado com sucesso"}), 201 # 201 Created

# Rota para o login de usuários existentes (método POST)
@app.route('/login', methods=['POST'])
def login():
    # Obtém os dados JSON enviados na requisição
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Verifica se nome de usuário e senha foram fornecidos
    if not username or not password:
        return jsonify({"message": "Nome de usuário e senha são obrigatórios"}), 400

    # Verifica se o nome de usuário existe no nosso "banco de dados"
    if username not in users_db:
        return jsonify({"message": "Nome de usuário ou senha inválidos"}), 401 # 401 Unauthorized

    # Obtém o hash da senha armazenada para o usuário
    hashed_password = users_db[username]

    # Verifica se a senha fornecida corresponde ao hash armazenado
    if check_password_hash(hashed_password, password):
        return jsonify({"message": "Login bem-sucedido"}), 200 # 200 OK
    else:
        return jsonify({"message": "Nome de usuário ou senha inválidos"}), 401 # 401 Unauthorized

# NOVA ROTA: Rota para verificar o status do servidor (método GET)
@app.route('/status', methods=['GET'])
def status():
    # Retorna uma mensagem simples para indicar que o servidor está online
    return jsonify({"message": "Servidor online"}), 200 # 200 OK

# Ponto de entrada para executar o aplicativo Flask
if __name__ == '__main__':
    # Roda o aplicativo no modo de depuração, o que é útil para desenvolvimento.
    # Em produção, você usaria um servidor WSGI como Gunicorn ou uWSGI.
    app.run(debug=True)
