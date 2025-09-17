import psycopg2
import psycopg2.extras
from flask_bcrypt import Bcrypt
import random
import string
# Configuração do banco PostgreSQL
DATABASE_URL = 'postgresql://neondb_owner:npg_gXAQk5D8aYFI@ep-blue-mouse-acwqphpx-pooler.sa-east-1.aws.neon.tech/efetivo-bm?sslmode=require&channel_binding=require'

bcrypt = Bcrypt()

def get_pg_connection():
    return psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)

def gerar_senha_temporaria(tamanho=12):
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(tamanho))

def migrar_senhas():
    conn = get_pg_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT id, email FROM usuarios")
    usuarios = cur.fetchall()

    for u in usuarios:
        nova_senha = gerar_senha_temporaria()
        senha_hash = bcrypt.generate_password_hash(nova_senha).decode()
        cur.execute("UPDATE usuarios SET senha=%s WHERE id=%s", (senha_hash, u['id']))
        print(f"Usuário {u['email']} atualizado com senha temporária: {nova_senha}")

    conn.commit()
    cur.close()
    conn.close()
    print("Migração concluída! Informe os usuários sobre suas senhas temporárias.")

if __name__ == '__main__':
    migrar_senhas()

