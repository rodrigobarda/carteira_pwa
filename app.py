import os
import psycopg2
import psycopg2.extras
from flask import Flask, request, jsonify, render_template, redirect, session, send_from_directory
from flask_cors import CORS
from werkzeug.utils import secure_filename
from datetime import datetime
import bcrypt
from google_drive_upload import upload_to_drive

app = Flask(__name__)
CORS(app)
app.secret_key = 'segredo123'  # Usado para sessão

# Configuração do banco PostgreSQL (Render)
DATABASE_URL = "postgresql://efetivo_bm_user:qeJWDJYQ7fMdy7xrTXhUyvGEkzeZrjcE@dpg-d1t95rur433s73cnkig0-a.oregon-postgres.render.com/efetivo_bm"

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
from flask import request, session, redirect, jsonify
import bcrypt

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    senha = data.get('senha')

    if not email or not senha:
        return jsonify({'erro': 'Email e senha são obrigatórios'}), 400

    usuario = query_db("SELECT * FROM usuarios WHERE email = %s", (email,), fetch=True)

    if usuario and bcrypt.checkpw(senha.encode(), usuario[0]['senha'].encode()):
        session['usuario'] = {
            'id': usuario[0]['id'],
            'nome': usuario[0]['nome'],
            'email': usuario[0]['email'],
            'perfil': usuario[0]['perfil']
        }

        # Redirecionamento baseado no perfil
        if usuario[0]['perfil'].lower() == 'admin':
            return jsonify({'redirect': '/admin.html'})
        else:
            efetivo = query_db("SELECT * FROM efetivo WHERE usuario_id = %s", (usuario[0]['id'],), fetch=True)
            if not efetivo:
                return jsonify({'erro': 'Efetivo não encontrado'}), 404
            return jsonify({'redirect': f"/carteira.html?usuario_id={efetivo[0]['usuario_id']}"})

    return jsonify({'erro': 'Credenciais inválidas'}), 401


# PROTEÇÃO manual nas rotas
def require_login_admin():
    if 'usuario' not in session or session['usuario']['perfil'] != 'admin':
        return False
    return True

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
    data = request.get_json()
    query_db("""INSERT INTO efetivo (nome, cpf, rg, matricula, posto, nascimento, admissao, foto, link_qrcode)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
             (data['nome'], data['cpf'], data['rg'], data['matricula'],
              data['posto'], data['nascimento'][:10], data['admissao'][:10],
              data.get('foto', ''), data.get('link_qrcode', '')))
    return jsonify({'status': 'Cadastrado com sucesso'})

@app.route('/efetivo/<int:id>', methods=['PUT'])
def atualizar_efetivo(id):
    if 'usuario' not in session or session['usuario']['perfil'] != 'admin':
        return jsonify({'erro': 'Acesso negado'}), 403

    try:
        form = request.form
        foto = request.files.get('foto')
        if not foto:
            return jsonify({'erro': 'A foto é obrigatória'}), 400

        from google_drive_upload import upload_to_drive
        filename = secure_filename(foto.filename)
        caminho_foto = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        foto.save(caminho_foto)

        # Faz upload no Google Drive
        foto_url = upload_to_drive(caminho_foto, filename)

        # Remove o arquivo local após o upload
        os.remove(caminho_foto)

        query_db("""UPDATE efetivo SET nome=%s, cpf=%s, rg=%s, matricula=%s, posto=%s,
                    nascimento=%s, admissao=%s, foto=%s, link_qrcode=%s WHERE id=%s""",
                (form['nome'], form['cpf'], form['rg'], form['matricula'], form['posto'],
                 form['nascimento'], form['admissao'], foto_url, form['link_qrcode'], id))
        
        return jsonify({'status': 'Atualizado com sucesso'})

    except Exception as e:
        return jsonify({'erro': str(e)}), 500


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

# Upload para Google Drive (mantido, caso esteja em uso)
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'usuario' not in session:
        return jsonify({'erro': 'Acesso negado'}), 403
    foto = request.files['foto']
    if not foto.filename:
        return jsonify({'erro': 'Arquivo inválido'}), 400
    filename = secure_filename(foto.filename)
    caminho = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    foto.save(caminho)
    url_drive = upload_to_drive(caminho, filename)
    os.remove(caminho)
    return jsonify({'foto': url_drive})

if __name__ == '__main__':
    #app.run(host='0.0.0.0', port=5000)
    app.run(debug=True)
