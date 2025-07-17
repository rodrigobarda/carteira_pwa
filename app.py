import os
import sqlite3
from flask import Flask, request, jsonify, send_from_directory, render_template, redirect
from flask_cors import CORS
from functools import wraps
import os
import bcrypt
import jwt
from datetime import datetime, timedelta, timezone
from werkzeug.utils import secure_filename

app = Flask(__name__)
CORS(app)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/admin.html')
def admin():
    return render_template('admin.html')

@app.route('/carteira.html')
def carteira():
    return render_template('carteira.html')

@app.route('/cadastro.html')
def cadastro():
    return render_template('cadastro.html')

@app.route('/logout')
def logout():
    return redirect('/')


UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['SECRET_KEY'] = 'segredo123'
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, 'efetivo_bm.sqlite')

def query_db(query, args=(), fetch=False):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # para acessar por nome: row['coluna']
    cur = conn.cursor()
    cur.execute(query, args)
    result = cur.fetchall() if fetch else None
    conn.commit()
    cur.close()
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
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            request.user = data
        except Exception as e:
            print("Erro token:", e)
            return jsonify({'erro': 'Token inválido'}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    senha = data.get('senha')

    if not email or not senha:
        return jsonify({'erro': 'Email e senha são obrigatórios'}), 400

    usuario = query_db("SELECT id, nome, email, senha, perfil FROM usuarios WHERE email = ?", (email,), fetch=True)

    if usuario:
        user = usuario[0]
        senha_hash = user['senha']
        if bcrypt.checkpw(senha.encode('utf-8'), senha_hash.encode('utf-8')):
            token = jwt.encode({
                'id': user['id'],
                'nome': user['nome'],
                'email': user['email'],
                'perfil': user['perfil'],
                'exp': datetime.now(timezone.utc) + timedelta(hours=6)
            }, app.config['SECRET_KEY'], algorithm="HS256")
            if isinstance(token, bytes):
                token = token.decode('utf-8')
            return jsonify({'token': token})

    return jsonify({'erro': 'Credenciais inválidas'}), 401

@app.route('/efetivo', methods=['GET'])
@token_required
def listar_efetivo():
    dados = query_db("SELECT id, nome, cpf, rg, matricula, posto, nascimento, admissao, foto, usuario_id, link_qrcode FROM efetivo", fetch=True)
    resultado = []
    for r in dados:
        resultado.append({
            'id': r['id'],
            'nome': r['nome'],
            'cpf': r['cpf'],
            'rg': r['rg'],
            'matricula': r['matricula'],
            'posto': r['posto'],
            'nascimento': r['nascimento'],
            'admissao': r['admissao'],
            'foto': r['foto'],
            'usuario_id': r['usuario_id'],
            'link_qrcode': r['link_qrcode'] or ''
        })
    return jsonify(resultado)

@app.route('/efetivo/<int:id>', methods=['GET'])
@token_required
def obter_efetivo(id):
    if request.user['perfil'] != 'admin':
        return jsonify({'erro': 'Acesso negado'}), 403

    resultado = query_db("SELECT id, nome, cpf, rg, matricula, posto, nascimento, admissao, foto, link_qrcode, usuario_id FROM efetivo WHERE id = ?", [id], fetch=True)
    
    if not resultado:
        return jsonify({'erro': 'Efetivo não encontrado'}), 404

    row = resultado[0]

    efetivo = {
        'id': row['id'],
        'nome': row['nome'],
        'cpf': row['cpf'],
        'rg': row['rg'],
        'matricula': row['matricula'],
        'posto': row['posto'],
        'nascimento': row['nascimento'][:10] if row['nascimento'] else None,
        'admissao': row['admissao'][:10] if row['admissao'] else None,
        'foto': row['foto'],
        'link_qrcode': row['link_qrcode'],
        'usuario_id': row['usuario_id'],
    }   

    return jsonify(efetivo)


@app.route('/efetivo', methods=['POST'])
@token_required
def adicionar_efetivo():
    if request.user['perfil'] != 'admin':
        return jsonify({'erro': 'Acesso negado'}), 403
    data = request.get_json()
    nascimento = data['nascimento'][:10] if data.get('nascimento') else None
    admissao = data['admissao'][:10] if data.get('admissao') else None

    query_db("""INSERT INTO efetivo (nome, cpf, rg, matricula, posto, nascimento, admissao, foto, link_qrcode) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""", (
        data['nome'], data['cpf'], data['rg'], data['matricula'],
        data['posto'], nascimento, admissao, data.get('foto', ''), data.get('link_qrcode', '')
    ))
    return jsonify({'status': 'Cadastrado com sucesso'})

@app.route('/efetivo/<int:id>', methods=['PUT'])
@token_required
def atualizar_efetivo(id):
    if request.user['perfil'] != 'admin':
        return jsonify({'erro': 'Acesso negado'}), 403

    # Verifica se o efetivo existe
    efetivo = query_db("SELECT foto, link_qrcode FROM efetivo WHERE id = ?", [id], fetch=True)
    if not efetivo:
        return jsonify({'erro': 'Efetivo não encontrado'}), 404

    dados = efetivo[0]
    foto_antiga = dados['foto']
    qrcode_antigo = dados['link_qrcode']

    nome = request.form.get('nome')
    cpf = request.form.get('cpf')
    rg = request.form.get('rg')
    matricula = request.form.get('matricula')
    posto = request.form.get('posto')
    nascimento = request.form.get('nascimento')
    admissao = request.form.get('admissao')
    link_qrcode = request.form.get('link_qrcode')

    # ✅ Se foto não for enviada, erro
    if 'foto' not in request.files or request.files['foto'].filename == '':
        return jsonify({'erro': 'Foto obrigatória'}), 400

    foto = request.files['foto']
    filename = secure_filename(foto.filename)
    caminho_foto = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    foto.save(caminho_foto)
    caminho_foto_db = f'/uploads/{filename}'

    # ✅ Verifica se link_qrcode foi enviado
    if not link_qrcode:
        return jsonify({'erro': 'Link do QRCode obrigatório'}), 400

    query_db("""
        UPDATE efetivo SET nome = ?, cpf = ?, rg = ?, matricula = ?, posto = ?, 
        nascimento = ?, admissao = ?, foto = ?, link_qrcode = ?
        WHERE id = ?
    """, [nome, cpf, rg, matricula, posto, nascimento, admissao, caminho_foto_db, link_qrcode, id])

    return jsonify({'status': 'Atualizado com sucesso'})

@app.route('/efetivo/<int:id>', methods=['DELETE'])
@token_required
def excluir_efetivo(id):
    if request.user['perfil'] != 'admin':
        return jsonify({'erro': 'Acesso negado'}), 403
    query_db("DELETE FROM efetivo WHERE id=?", (id,))
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
    resultado = [{'id': u['id'], 'nome': u['nome'], 'email': u['email'], 'perfil': u['perfil']} for u in usuarios]
    return jsonify(resultado)

@app.route('/usuarios/<int:id>', methods=['GET'])
@token_required
def obter_usuario(id):
    if request.user['perfil'] != 'admin':
        return jsonify({'erro': 'Acesso negado'}), 403
    usuario = query_db("SELECT id, nome, email, perfil FROM usuarios WHERE id = ?", (id,), fetch=True)
    if not usuario:
        return jsonify({'erro': 'Usuário não encontrado'}), 404
    u = usuario[0]
    return jsonify({'id': u['id'], 'nome': u['nome'], 'email': u['email'], 'perfil': u['perfil']})

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
            "UPDATE usuarios SET nome=?, email=?, senha=?, perfil=? WHERE id=?",
            (nome, email, senha_hash, perfil, id)
        )
    else:
        query_db(
            "UPDATE usuarios SET nome=?, email=?, perfil=? WHERE id=?",
            (nome, email, perfil, id)
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

    # Inserir usuário
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO usuarios (nome, email, senha, perfil) VALUES (?, ?, ?, ?)",
        (nome, email, hashed, perfil)
    )
    novo_usuario_id = cur.lastrowid

    # Atualizar usuário na tabela efetivo se efetivo_id informado
    if efetivo_id and str(efetivo_id).isdigit():
        cur.execute(
            "UPDATE efetivo SET usuario_id = ? WHERE id = ?",
            (novo_usuario_id, int(efetivo_id))
        )

    conn.commit()
    cur.close()
    conn.close()

    return jsonify({'status': 'Cadastrado com sucesso', 'usuario_id': novo_usuario_id})

@app.route('/upload', methods=['POST'])
@token_required
def upload_file():
    if 'foto' not in request.files:
        return jsonify({'erro': 'Nenhum arquivo enviado'}), 400
    foto = request.files['foto']
    if foto.filename == '':
        return jsonify({'erro': 'Nenhum arquivo selecionado'}), 400
    filename = secure_filename(foto.filename)
    caminho = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    foto.save(caminho)
    caminho_url = f'/uploads/{filename}'
    return jsonify({'foto': caminho_url})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
