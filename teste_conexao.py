import mysql.connector

try:
    conexao = mysql.connector.connect(
        host="127.0.0.1",
        user="root",
        password="",
        database="efetivo_bm"
    )

    if conexao.is_connected():
        print("✅ Conexão bem-sucedida com o banco de dados!")
        cursor = conexao.cursor()
        cursor.execute("SHOW TABLES;")
        print("📋 Tabelas existentes:")
        for tabela in cursor.fetchall():
            print(" -", tabela[0])

except mysql.connector.Error as erro:
    print("❌ Erro ao conectar ao MySQL:", erro)

finally:
    if 'conexao' in locals() and conexao.is_connected():
        conexao.close()
