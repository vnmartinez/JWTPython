from flask import Flask, request, jsonify
import jwt
import datetime
import bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = 'senha123'  # Troque pelo seu segredo secreto

# Banco de dados fictício para armazenar informações do usuário (substitua por um banco de dados real)
users_db = {}

# Rota para criar uma nova conta de usuário
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Verifique se o nome de usuário já existe
    if username in users_db:
        return jsonify({'message': 'Nome de usuário já existe'}), 400

    # Hash da senha antes de armazená-la (usando bcrypt)
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Armazene o nome de usuário e a senha hash (substitua por um banco de dados real)
    users_db[username] = hashed_password

    return jsonify({'message': 'Usuário registrado com sucesso'}), 201

# Rota de login para gerar tokens JWT
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Verifique as credenciais do usuário (exemplo simples)
    if username == 'usuario' and password == 'senha':
        token = jwt.encode({'username': username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)}, app.config['SECRET_KEY'], algorithm='HS256')

        return jsonify({'token': token})

    return jsonify({'message': 'Credenciais inválidas'}), 401

# Middleware para verificar o token JWT
def verify_token(token):
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return data
    except jwt.ExpiredSignatureError:
        return None  # Token expirado
    except jwt.InvalidTokenError:
        return None  # Token inválido

# Rota protegida
@app.route('/protegida', methods=['GET'])
def protegida():
    token = request.headers.get('Authorization')

    if not token:
        return jsonify({'message': 'Token não fornecido'}), 401

    data = verify_token(token)

    if not data:
        return jsonify({'message': 'Token inválido'}), 401

    return jsonify({'message': 'Esta é uma rota protegida'})

if __name__ == '__main__':
    app.run(debug=True)
