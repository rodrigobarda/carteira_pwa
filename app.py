from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import mysql.connector
import os
import jwt
import bcrypt
import datetime
from functools import wraps
from werkzeug.utils import secure_filename

app = Flask(__name__)
CORS(app)

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

SECRET_KEY = 'segredo123'

DB_CONFIG = {
    'host': '127.0.0.1',
    'user': 'root',
    'password': '',
    'database': 'efetivo_bm'
}

def query_db(query, args=(), fetch=False):
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor()
    cursor.execute(query, args)
    result = cursor.fetchall() if fetch else None
    conn.commit()
    cursor.close()
    conn.close()
    return result

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'erro': 'Token ausente'}), 401
        try:
            token = token.split()[1]
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            request.user = data
        except Exception as e:
            print("Erro token:", e)
            return jsonify({'erro': 'Token inválido'}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    print("Dados recebidos no login:", data)  # debug

    user = query_db("SELECT id, nome, email, senha, perfil FROM usuarios WHERE email=%s", [data['email']], fetch=True)
    
    if user:
        senha_hash = user[0][3]
        print("Hash armazenado:", senha_hash)  # debug
        print("Senha digitada:", data['senha'])  # debug

        if bcrypt.checkpw(data['senha'].encode('utf-8'), senha_hash.encode('utf-8')):
            token = jwt.encode({
                'id': user[0][0],
                'nome': user[0][1],
                'email': user[0][2],
                'perfil': user[0][4],
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=6)
            }, SECRET_KEY, algorithm="HS256")

            if isinstance(token, bytes):
                token = token.decode('utf-8')
            
            return jsonify({'token': token})
        else:
            print("❌ Senha inválida")
            senha = 'admin123'
            hash = bcrypt.hashpw(senha.encode(), bcrypt.gensalt())
            print(hash.decode())  # <- copie o resultado
    else:
        print("❌ Usuário não encontrado")
        
    return jsonify({'erro': 'Credenciais inválidas'}), 401


@app.route('/efetivo', methods=['GET'])
@token_required
def listar_efetivo():
    dados = query_db("SELECT id, nome, cpf, rg, matricula, posto, nascimento, admissao, foto, usuario_id, link_qrcode FROM efetivo", fetch=True)
    return jsonify([{
        'id': r[0],
        'nome': r[1],
        'cpf': r[2],
        'rg': r[3],
        'matricula': r[4],
        'posto': r[5],
        'nascimento': str(r[6]),
        'admissao': str(r[7]),
        'foto': r[8],
        'usuario_id': r[9],
        'link_qrcode': r[10] or ''
    } for r in dados])

@app.route('/efetivo/<int:id>', methods=['GET'])
@token_required
def obter_efetivo(id):
    dados = query_db("SELECT id, nome, cpf, rg, matricula, posto, nascimento, admissao, foto, link_qrcode FROM efetivo WHERE id=%s", [id], fetch=True)

    if not dados:
        return jsonify({'erro': 'Efetivo não encontrado'}), 404

    r = dados[0]

    nascimento = r[6].strftime('%Y-%m-%d') if r[6] else ''
    admissao = r[7].strftime('%Y-%m-%d') if r[7] else ''

    return jsonify({
        'id': r[0],
        'nome': r[1],
        'cpf': r[2],
        'rg': r[3],
        'matricula': r[4],
        'posto': r[5],
        'nascimento': nascimento,
        'admissao': admissao,
        'foto': r[8],
        'link_qrcode': r[9] or ''
    })

@app.route('/efetivo', methods=['POST'])
@token_required
def adicionar_efetivo():
    if request.user['perfil'] != 'admin':
        return jsonify({'erro': 'Acesso negado'}), 403
    data = request.get_json()
    query_db("""INSERT INTO efetivo (nome, cpf, rg, matricula, posto, nascimento, admissao, foto, link_qrcode) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""", [
        data['nome'], data['cpf'], data['rg'], data['matricula'],
        data['posto'], data['nascimento'], data['admissao'], data.get('foto', ''), data.get('link_qrcode', '')
    ])
    return jsonify({'status': 'ok'})

@app.route('/efetivo/<int:id>', methods=['PUT'])
@token_required
def atualizar_efetivo(id):
    if request.user['perfil'] != 'admin':
        return jsonify({'erro': 'Acesso negado'}), 403

    dados_existentes = query_db("SELECT foto, link_qrcode FROM efetivo WHERE id=%s", [id], fetch=True)
    if not dados_existentes:
        return jsonify({'erro': 'Efetivo não encontrado'}), 404

    nome = request.form.get('nome')
    cpf = request.form.get('cpf')
    rg = request.form.get('rg')
    matricula = request.form.get('matricula')
    posto = request.form.get('posto')
    nascimento = request.form.get('nascimento')
    admissao = request.form.get('admissao')

    foto = request.files.get('foto')
    link_qrcode_novo = request.form.get('link_qrcode')

    # ✅ Foto obrigatória
    if not foto or foto.filename.strip() == '':
        return jsonify({'erro': 'Foto obrigatória'}), 400

    # ✅ QR Code obrigatório
    if not link_qrcode_novo or link_qrcode_novo.strip() == '':
        return jsonify({'erro': 'Link QR Code obrigatório'}), 400

    # ✅ Salva nova foto
    filename = secure_filename(foto.filename)
    caminho_salvar = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    foto.save(caminho_salvar)
    caminho_foto = f'/uploads/{filename}'

    query_db("""
        UPDATE efetivo SET nome=%s, cpf=%s, rg=%s, matricula=%s, posto=%s,
        nascimento=%s, admissao=%s, foto=%s, link_qrcode=%s
        WHERE id=%s
    """, [nome, cpf, rg, matricula, posto, nascimento, admissao, caminho_foto, link_qrcode_novo, id])

    return jsonify({'status': 'Efetivo atualizado com sucesso'})


    query_db("""
        UPDATE efetivo SET nome=%s, cpf=%s, rg=%s, matricula=%s, posto=%s, nascimento=%s, admissao=%s, foto=%s, link_qrcode=%s
        WHERE id=%s
    """, [nome, cpf, rg, matricula, posto, nascimento, admissao, caminho_foto, link_qrcode_novo, id])

    return jsonify({'status': 'ok'})

@app.route('/efetivo/<int:id>', methods=['DELETE'])
@token_required
def excluir_efetivo(id):
    if request.user['perfil'] != 'admin':
        return jsonify({'erro': 'Acesso negado'}), 403
    query_db("DELETE FROM efetivo WHERE id=%s", [id])
    return jsonify({'status': 'excluído'})

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/usuarios')
@token_required
def listar_usuarios():
    if request.user['perfil'] != 'admin':
        return jsonify({'erro': 'Acesso negado'}), 403

    usuarios = query_db("SELECT id, nome, email, perfil FROM usuarios", fetch=True)
    resultado = [{'id': u[0], 'nome': u[1], 'email': u[2], 'perfil': u[3]} for u in usuarios]
    return jsonify(resultado)

@app.route('/usuarios/<int:id>', methods=['GET'])
@token_required
def obter_usuario(id):
    if request.user['perfil'] != 'admin':
        return jsonify({'erro': 'Acesso negado'}), 403

    try:
        usuario = query_db(
            "SELECT id, nome, email, perfil FROM usuarios WHERE id = %s",
            [id],
            fetch=True
        )

        if not usuario:
            return jsonify({'erro': 'Usuário não encontrado'}), 404

        u = usuario[0]
        return jsonify({
            'id': u[0],
            'nome': u[1],
            'email': u[2],
            'perfil': u[3]
        })

    except Exception as e:
        print("Erro ao buscar usuário:", e)
        return jsonify({'erro': 'Erro interno ao buscar usuário'}), 500

@app.route('/usuarios/<int:id>', methods=['PUT'])
@token_required
def atualizar_usuario(id):
    if request.user['perfil'] != 'admin':
        return jsonify({'erro': 'Acesso negado'}), 403

    dados = request.get_json()

    nome = dados.get('nome')
    email = dados.get('email')
    senha = dados.get('senha')
    perfil = dados.get('perfil')

    if not nome or not email or not perfil:
        return jsonify({'erro': 'Campos obrigatórios ausentes'}), 400

    if senha:
        senha_hash = bcrypt.hashpw(senha.encode(), bcrypt.gensalt()).decode()
        query_db(
            "UPDATE usuarios SET nome=%s, email=%s, senha=%s, perfil=%s WHERE id=%s",
            [nome, email, senha_hash, perfil, id]
        )
    else:
        query_db(
            "UPDATE usuarios SET nome=%s, email=%s, perfil=%s WHERE id=%s",
            [nome, email, perfil, id]
        )

    return jsonify({'status': 'Usuário atualizado com sucesso'})

@app.route('/usuarios', methods=['POST'])
@token_required
def cadastrar_usuario():
    if request.user['perfil'] != 'admin':
        return jsonify({'erro': 'Acesso negado'}), 403

    data = request.get_json()
    nome = data.get('nome')
    email = data.get('email')
    senha = data.get('senha')
    perfil = data.get('perfil')
    efetivo_id = data.get('efetivo_id')

    if not all([nome, email, senha, perfil]):
        return jsonify({'erro': 'Dados obrigatórios incompletos'}), 400

    hashed = bcrypt.hashpw(senha.encode(), bcrypt.gensalt()).decode()

    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()

        cursor.execute(
            "INSERT INTO usuarios (nome, email, senha, perfil) VALUES (%s, %s, %s, %s)",
            (nome, email, hashed, perfil)
        )
        novo_usuario_id = cursor.lastrowid

        if efetivo_id and str(efetivo_id).isdigit():
            cursor.execute(
                "UPDATE efetivo SET usuario_id = %s WHERE id = %s",
                (novo_usuario_id, int(efetivo_id))
            )

        conn.commit()
        return jsonify({'status': 'ok', 'usuario_id': novo_usuario_id})

    except mysql.connector.Error as err:
        print("Erro MySQL:", err)
        return jsonify({'erro': 'Erro ao salvar no banco de dados'}), 500

    finally:
        if cursor: cursor.close()
        if conn: conn.close()

if __name__ == '__main__':
    app.run(debug=True)
