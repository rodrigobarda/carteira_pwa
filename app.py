import os
import psycopg2
import psycopg2.extras
from flask import Flask, request, jsonify, render_template, redirect, session, send_from_directory
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
from datetime import datetime
import bcrypt
import jwt

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = "senha123"
app.secret_key = "senha123"
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
CORS(app)
# Configuração do banco Postg
# reSQL (Render)
DATABASE_URL = 'postgresql://neondb_owner:npg_gXAQk5D8aYFI@ep-blue-mouse-acwqphpx-pooler.sa-east-1.aws.neon.tech/efetivo-bm?sslmode=require&channel_binding=require'

# Pasta de uploads
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Conexão
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

# ROTAS HTML protegidas
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/admin.html')
def admin():
    if 'usuario' not in session:
        return redirect('/')
    return render_template('admin.html')

@app.route('/cadastro.html')
def cadastro():
    if 'usuario' not in session or session['usuario']['perfil'] != 'admin':
        return redirect('/')
    return render_template('cadastro.html')

@app.route('/carteira.html')
def carteira():
    return render_template('carteira.html')

@app.route('/logout')
def logout():
    session.pop('usuario', None)
    return redirect('/')

# LOGIN
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get("email")
    senha = data.get("senha")

    conn = get_pg_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT id, email, senha, perfil FROM usuarios WHERE email = %s", (email,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    if user and bcrypt.check_password_hash(user["senha"], senha):
        access_token = create_access_token(identity={"id": user["id"], "email": user["email"], "perfil": user["perfil"]})
        session['usuario'] = {"id": user["id"], "email": user["email"], "perfil": user["perfil"]}
        redirect_url = "/admin.html" if user["perfil"].lower() == "admin" else f"/carteira.html?usuario_id={user['id']}"
        return jsonify({"redirect": redirect_url, "token": access_token})

    return jsonify({"erro": "Credenciais inválidas"}), 401

# PROTEÇÃO manual nas rotas
def require_login_admin():
    if 'usuario' not in session or session['usuario']['perfil'] != 'admin':
        return False
    return True

@app.route('/efetivo/<int:usuario_id>', methods=['GET'])
@jwt_required()
def get_efetivo(usuario_id):
    conn = get_pg_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM efetivo WHERE usuario_id = %s", (usuario_id,))
    efetivo = cur.fetchone()
    cur.close()
    conn.close()

    if not efetivo:
        return jsonify({'erro': 'Efetivo não encontrado'}), 404

    return jsonify(efetivo)


# CRUD EFETIVO
@app.route('/efetivo', methods=['GET'])
def listar_efetivo():
    if 'usuario' not in session:
        return jsonify({'erro': 'Acesso negado'}), 403
    dados = query_db("SELECT * FROM efetivo", fetch=True)
    return jsonify(dados)

@app.route('/efetivo/<int:id>', methods=['GET'])
def obter_efetivo(id):
    if 'usuario' not in session:
        return jsonify({'erro': 'Acesso negado'}), 403

    dados = query_db("SELECT * FROM efetivo WHERE id = %s", (id,), fetch=True)

    if not dados:
        return jsonify({'erro': 'Efetivo não encontrado'}), 404

    return jsonify(dados[0])


@app.route('/efetivo', methods=['POST'])
def adicionar_efetivo():
    if not require_login_admin():
        return jsonify({'erro': 'Acesso negado'}), 403

    form = request.form
    foto = request.files.get('foto')

    if not foto:
        return jsonify({'erro': 'Foto é obrigatória'}), 400

    filename = secure_filename(foto.filename)
    caminho_foto = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    foto.save(caminho_foto)
    foto_url = f'/uploads/{filename}'

    query_db("""INSERT INTO efetivo (nome, cpf, rg, matricula, posto, nascimento, admissao, foto, link_qrcode)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
             (form['nome'], form['cpf'], form['rg'], form['matricula'],
              form['posto'], form['nascimento'][:10], form['admissao'][:10],
              foto_url, form.get('link_qrcode', '')))

    return jsonify({'status': 'Cadastrado com sucesso'})


@app.route('/efetivo/<int:id>', methods=['PUT'])
def atualizar_efetivo(id):
    if not require_login_admin():
        return jsonify({'erro': 'Acesso negado'}), 403

    form = request.form
    foto = request.files.get('foto')

    if foto:
        filename = secure_filename(foto.filename)
        caminho_foto = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        foto.save(caminho_foto)
        foto_url = f'/uploads/{filename}'

        query_db("""
            UPDATE efetivo SET
            nome=%s, cpf=%s, rg=%s, matricula=%s, posto=%s,
            nascimento=%s, admissao=%s, foto=%s, link_qrcode=%s
            WHERE id=%s
            """,
            (form['nome'], form['cpf'], form['rg'], form['matricula'],
             form['posto'], form['nascimento'][:10], form['admissao'][:10],
             foto_url, form.get('link_qrcode', ''), id))
    else:
        # Sem foto nova, manter a foto antiga
        query_db("""
            UPDATE efetivo SET
            nome=%s, cpf=%s, rg=%s, matricula=%s, posto=%s,
            nascimento=%s, admissao=%s, link_qrcode=%s
            WHERE id=%s
            """,
            (form['nome'], form['cpf'], form['rg'], form['matricula'],
             form['posto'], form['nascimento'][:10], form['admissao'][:10],
             form.get('link_qrcode', ''), id))

    return jsonify({'status': 'Atualizado com sucesso'})



@app.route('/efetivo/<int:id>', methods=['DELETE'])
def excluir_efetivo(id):
    if not require_login_admin():
        return jsonify({'erro': 'Acesso negado'}), 403
    query_db("DELETE FROM efetivo WHERE id = %s", (id,))
    return jsonify({'status': 'Excluído'})

# USUÁRIOS
@app.route('/usuarios', methods=['GET'])
def listar_usuarios():
    if not require_login_admin():
        return jsonify({'erro': 'Acesso negado'}), 403
    return jsonify(query_db("SELECT id, nome, email, perfil FROM usuarios", fetch=True))

@app.route('/usuarios/<int:id>', methods=['GET'])
def obter_usuario(id):
    if not require_login_admin():
        return jsonify({'erro': 'Acesso negado'}), 403

    usuario = query_db("SELECT id, nome, email, perfil FROM usuarios WHERE id = %s", (id,), fetch=True)
    
    if not usuario:
        return jsonify({'erro': 'Usuário não encontrado'}), 404
    
    return jsonify(usuario[0])

@app.route('/usuarios', methods=['POST'])
def cadastrar_usuario():
    if not require_login_admin():
        return jsonify({'erro': 'Acesso negado'}), 403
    data = request.get_json()
    senha_hash = bcrypt.hashpw(data['senha'].encode(), bcrypt.gensalt()).decode()
    conn = get_pg_connection()
    cur = conn.cursor()
    cur.execute("INSERT INTO usuarios (nome, email, senha, perfil) VALUES (%s, %s, %s, %s) RETURNING id",
                (data['nome'], data['email'], senha_hash, data['perfil']))
    usuario_id = cur.fetchone()['id']
    if data.get('efetivo_id'):
        cur.execute("UPDATE efetivo SET usuario_id = %s WHERE id = %s", (usuario_id, data['efetivo_id']))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({'status': 'Usuário cadastrado', 'usuario_id': usuario_id})

@app.route('/usuarios/<int:id>', methods=['PUT'])
def atualizar_usuario(id):
    if not require_login_admin():
        return jsonify({'erro': 'Acesso negado'}), 403

    if not request.is_json:
        return jsonify({'erro': 'Tipo de conteúdo não suportado. Use application/json'}), 415

    data = request.get_json()
    
    if data.get('senha'):
        senha_hash = bcrypt.hashpw(data['senha'].encode(), bcrypt.gensalt()).decode()
        query_db("UPDATE usuarios SET nome=%s, email=%s, senha=%s, perfil=%s WHERE id=%s",
                 (data['nome'], data['email'], senha_hash, data['perfil'], id))
    else:
        query_db("UPDATE usuarios SET nome=%s, email=%s, perfil=%s WHERE id=%s",
                 (data['nome'], data['email'], data['perfil'], id))
    
    return jsonify({'status': 'Usuário atualizado'})


@app.route('/usuarios/<int:id>', methods=['DELETE'])
def excluir_usuario(id):
    if not require_login_admin():
        return jsonify({'erro': 'Acesso negado'}), 403
    conn = get_pg_connection()
    cur = conn.cursor()
    cur.execute("UPDATE efetivo SET usuario_id = NULL WHERE usuario_id = %s", (id,))
    cur.execute("DELETE FROM usuarios WHERE id = %s", (id,))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({'status': 'Usuário excluído'})


@app.route('/upload', methods=['POST'])
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

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


if __name__ == '__main__':
    #app.run(host='0.0.0.0', port=5000)
    app.run(debug=True)
