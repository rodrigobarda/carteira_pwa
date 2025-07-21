import os
import psycopg2
import psycopg2.extras
from flask import Flask, request, jsonify, send_from_directory, render_template, redirect
from flask_cors import CORS
from functools import wraps
import bcrypt
import jwt
from datetime import datetime, timedelta, timezone
from werkzeug.utils import secure_filename

app = Flask(__name__)
CORS(app)

# ROTAS HTML
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

# UPLOADS
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# CONFIG
app.config['SECRET_KEY'] = 'segredo123'
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://efetivo_bm_user:qeJWDJYQ7fMdy7xrTXhUyvGEkzeZrjcE@dpg-d1t95rur433s73cnkig0-a.oregon-postgres.render.com/efetivo_bm")

def get_pg_connection():
    return psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)

def query_db(query, args=(), fetch=False):
    conn = get_pg_connection()
    cur = conn.cursor()
    cur.execute(query, args)
    result = cur.fetchall() if fetch else None
    conn.commit()
    cur.close()
    conn.close()
    return result

# AUTENTICAÇÃO
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

    usuario = query_db("SELECT id, nome, email, senha, perfil FROM usuarios WHERE email = %s", (email,), fetch=True)
    if usuario:
        user = usuario[0]
        senha_hash = user['senha']
        if bcrypt.checkpw(senha.encode(), senha_hash.encode()):
            token = jwt.encode({
                'id': user['id'],
                'nome': user['nome'],
                'email': user['email'],
                'perfil': user['perfil'],
                'exp': datetime.now(timezone.utc) + timedelta(hours=6)
            }, app.config['SECRET_KEY'], algorithm="HS256")
            return jsonify({'token': token if isinstance(token, str) else token.decode()})
    return jsonify({'erro': 'Credenciais inválidas'}), 401

# EFETIVO
@app.route('/efetivo', methods=['GET'])
@token_required
def listar_efetivo():
    dados = query_db("SELECT * FROM efetivo", fetch=True)
    return jsonify(dados)

@app.route('/efetivo/<int:id>', methods=['GET'])
@token_required
def obter_efetivo(id):
    if request.user['perfil'] != 'admin':
        return jsonify({'erro': 'Acesso negado'}), 403
    dados = query_db("SELECT * FROM efetivo WHERE id = %s", (id,), fetch=True)
    if not dados:
        return jsonify({'erro': 'Efetivo não encontrado'}), 404
    return jsonify(dados[0])

@app.route('/efetivo', methods=['POST'])
@token_required
def adicionar_efetivo():
    if request.user['perfil'] != 'admin':
        return jsonify({'erro': 'Acesso negado'}), 403
    data = request.get_json()
    nascimento = data.get('nascimento')[:10] if data.get('nascimento') else None
    admissao = data.get('admissao')[:10] if data.get('admissao') else None
    query_db("""INSERT INTO efetivo (nome, cpf, rg, matricula, posto, nascimento, admissao, foto, link_qrcode)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
             (data['nome'], data['cpf'], data['rg'], data['matricula'],
              data['posto'], nascimento, admissao, data.get('foto', ''), data.get('link_qrcode', '')))
    return jsonify({'status': 'Cadastrado com sucesso'})

@app.route('/efetivo/<int:id>', methods=['PUT'])
@token_required
def atualizar_efetivo(id):
    if request.user['perfil'] != 'admin':
        return jsonify({'erro': 'Acesso negado'}), 403

    nome = request.form.get('nome')
    cpf = request.form.get('cpf')
    rg = request.form.get('rg')
    matricula = request.form.get('matricula')
    posto = request.form.get('posto')
    nascimento = request.form.get('nascimento')
    admissao = request.form.get('admissao')
    link_qrcode = request.form.get('link_qrcode')

    if 'foto' not in request.files or request.files['foto'].filename == '':
        return jsonify({'erro': 'Foto obrigatória'}), 400

    foto = request.files['foto']
    filename = secure_filename(foto.filename)
    caminho_foto = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    foto.save(caminho_foto)
    caminho_foto_db = f'/uploads/{filename}'

    if not link_qrcode:
        return jsonify({'erro': 'Link do QRCode obrigatório'}), 400

    query_db("""UPDATE efetivo SET nome=%s, cpf=%s, rg=%s, matricula=%s, posto=%s,
                nascimento=%s, admissao=%s, foto=%s, link_qrcode=%s WHERE id=%s""",
             (nome, cpf, rg, matricula, posto, nascimento, admissao, caminho_foto_db, link_qrcode, id))
    return jsonify({'status': 'Atualizado com sucesso'})

@app.route('/efetivo/<int:id>', methods=['DELETE'])
@token_required
def excluir_efetivo(id):
    if request.user['perfil'] != 'admin':
        return jsonify({'erro': 'Acesso negado'}), 403
    query_db("DELETE FROM efetivo WHERE id=%s", (id,))
    return jsonify({'status': 'Excluído'})

# USUÁRIOS
@app.route('/usuarios', methods=['GET'])
@token_required
def listar_usuarios():
    if request.user['perfil'] != 'admin':
        return jsonify({'erro': 'Acesso negado'}), 403
    dados = query_db("SELECT id, nome, email, perfil FROM usuarios", fetch=True)
    return jsonify(dados)

@app.route('/usuarios/<int:id>', methods=['GET'])
@token_required
def obter_usuario(id):
    if request.user['perfil'] != 'admin':
        return jsonify({'erro': 'Acesso negado'}), 403
    dados = query_db("SELECT id, nome, email, perfil FROM usuarios WHERE id = %s", (id,), fetch=True)
    if not dados:
        return jsonify({'erro': 'Usuário não encontrado'}), 404
    return jsonify(dados[0])

@app.route('/usuarios/<int:id>', methods=['PUT'])
@token_required
def atualizar_usuario(id):
    if request.user['perfil'] != 'admin':
        return jsonify({'erro': 'Acesso negado'}), 403
    dados = request.get_json()
    if dados.get('senha'):
        senha_hash = bcrypt.hashpw(dados['senha'].encode(), bcrypt.gensalt()).decode()
        query_db("UPDATE usuarios SET nome=%s, email=%s, senha=%s, perfil=%s WHERE id=%s",
                 (dados['nome'], dados['email'], senha_hash, dados['perfil'], id))
    else:
        query_db("UPDATE usuarios SET nome=%s, email=%s, perfil=%s WHERE id=%s",
                 (dados['nome'], dados['email'], dados['perfil'], id))
    return jsonify({'status': 'Usuário atualizado com sucesso'})

@app.route('/usuarios', methods=['POST'])
@token_required
def cadastrar_usuario():
    if request.user['perfil'] != 'admin':
        return jsonify({'erro': 'Acesso negado'}), 403
    data = request.get_json()
    if not all([data.get('nome'), data.get('email'), data.get('senha'), data.get('perfil')]):
        return jsonify({'erro': 'Dados obrigatórios incompletos'}), 400
    senha_hash = bcrypt.hashpw(data['senha'].encode(), bcrypt.gensalt()).decode()
    conn = get_pg_connection()
    cur = conn.cursor()
    cur.execute("""INSERT INTO usuarios (nome, email, senha, perfil) VALUES (%s, %s, %s, %s) RETURNING id""",
                (data['nome'], data['email'], senha_hash, data['perfil']))
    usuario_id = cur.fetchone()['id']
    if data.get('efetivo_id'):
        cur.execute("UPDATE efetivo SET usuario_id = %s WHERE id = %s", (usuario_id, data['efetivo_id']))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({'status': 'Cadastrado com sucesso', 'usuario_id': usuario_id})

# ROTA PARA ARQUIVOS ESTÁTICOS (imagens/fotos)
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    #app.run(host='0.0.0.0', port=5000)
    app.run(debug=True)
