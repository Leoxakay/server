# Importa os módulos necessários do Flask
from flask import Flask, request, jsonify
# Importa o CORS para permitir requisições de origens diferentes (do HTML para o Flask)
from flask_cors import CORS
# Importa ferramentas de segurança para hashing de senhas
from werkzeug.security import generate_password_hash, check_password_hash
import os # Importa o módulo os para acessar variáveis de ambiente

# Cria uma instância do aplicativo Flask
app = Flask(__name__)
# Habilita o CORS para todas as rotas.
# Em produção, é RECOMENDADO restringir isso a domínios específicos.
# Por exemplo, CORS(app, resources={r"/*": {"origins": "https://seu-frontend.onrender.com"}})
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

# Rota para verificar o status do servidor (método GET)
@app.route('/status', methods=['GET'])
def status():
    # Retorna uma mensagem simples para indicar que o servidor está online
    return jsonify({"message": "Servidor online"}), 200 # 200 OK

# Rota para obter a lista de todos os usuários cadastrados (método GET)
@app.route('/users', methods=['GET'])
def get_users():
    # Retorna uma lista dos nomes de usuário (as chaves do dicionário users_db)
    # ATENÇÃO: Em um sistema real, essa rota PRECISA ser protegida por autenticação e autorização
    # para evitar que qualquer um acesse a lista de usuários.
    return jsonify(list(users_db.keys())), 200 # 200 OK

# Ponto de entrada para executar o aplicativo Flask
if __name__ == '__main__':
    # Obtém a porta do ambiente (fornecida pelo Render) ou usa 5000 para desenvolvimento local.
    port = int(os.environ.get("PORT", 5000))
    # Em produção, o Gunicorn ou outro servidor WSGI cuidará de expor a aplicação.
    # Para desenvolvimento local, ele rodará em 127.0.0.1:5000 por padrão.
    # No Render, ele será acessível externamente na porta fornecida pelo ambiente.
    app.run(host='0.0.0.0', port=port, debug=True)
