# webapp-storage
Web Application per le prenotazioni degli spazi comuni

# WebApp con Flask, MinIO e Mailjet 🚀

Questa è una web app Flask che utilizza MinIO per l'archiviazione, Flask-Login per la gestione utenti e Mailjet per l'invio delle email.

## **🔧 Setup dell'Ambiente**
1. **Clonare il repository**
   ```bash
   git clone https://github.com/tuo-username/webapp-storage.git
   cd webapp-storage

**Installare le dipendenze*
pip install -r requirements.txt

**Avviare MinIO in un container Docker*
docker run -d --name minio \
    -p 9000:9000 -p 9001:9001 \
    -e "MINIO_ROOT_USER=minioadmin" \
    -e "MINIO_ROOT_PASSWORD=minioadmin" \
    quay.io/minio/minio server /data --console-address ":9001"

Username: minioadmin
Password: minioadmin


python app.py