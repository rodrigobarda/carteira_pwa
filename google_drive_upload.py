import os
import io
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload

# Caminho para seu arquivo JSON com as credenciais de conta de serviço
SERVICE_ACCOUNT_FILE = 'credenciais_drive.json'

SCOPES = ['https://www.googleapis.com/auth/drive.file']
FOLDER_ID = '1UUmm762VLzC19s1XjzcFo1ulhGYlndJR'  # crie uma pasta no Google Drive e use o ID dela aqui

def upload_to_drive(file_path, file_name):
    credentials = service_account.Credentials.from_service_account_file(
        SERVICE_ACCOUNT_FILE, scopes=SCOPES)

    service = build('drive', 'v3', credentials=credentials)

    file_metadata = {
        'name': file_name,
        'parents': [FOLDER_ID]
    }

    media = MediaFileUpload(file_path, mimetype='image/jpeg')
    file = service.files().create(
        body=file_metadata,
        media_body=media,
        fields='id, webViewLink, webContentLink'
    ).execute()

    return file.get('webContentLink')  # ou 'webViewLink' se quiser link visual
