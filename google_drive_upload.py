import os
import io
import json
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload

# Lê as credenciais do JSON carregado por variável de ambiente
SERVICE_ACCOUNT_INFO = os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON")

# Você também pode definir o ID da pasta por variável de ambiente
FOLDER_ID = os.getenv("GOOGLE_DRIVE_FOLDER_ID")

def upload_to_drive(file_path, file_name):
    if not SERVICE_ACCOUNT_INFO or not FOLDER_ID:
        raise Exception("Credenciais do Google Drive ou ID da pasta não foram configurados")

    # Converte string JSON para dicionário
    info = json.loads(SERVICE_ACCOUNT_INFO)
    
    credentials = service_account.Credentials.from_service_account_info(
        info, scopes=['https://www.googleapis.com/auth/drive.file'])

    service = build('drive', 'v3', credentials=credentials)

    file_metadata = {
        'name': file_name,
        'parents': [FOLDER_ID]
    }

    media = MediaFileUpload(file_path, mimetype='image/jpeg')

    uploaded = service.files().create(
        body=file_metadata,
        media_body=media,
        fields='id, webViewLink, webContentLink'
    ).execute()

    return uploaded.get('webContentLink')  # link para download direto

