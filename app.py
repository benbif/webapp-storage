import os 
import bcrypt
import json
import io
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_wtf import FlaskForm
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_session import Session
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Regexp
from mailjet_rest import Client
from itsdangerous import URLSafeTimedSerializer
from minio import Minio
from datetime import datetime, timezone

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'  # Cambia questa chiave con una più sicura!
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Configura MinIO
#MINIO_URL = "http://127.0.0.1:9000"
MINIO_URL = "127.0.0.1:9000"  # Rimuovi "http://"
MINIO_ACCESS_KEY = "k3ZnNJGIEiI2INiTOCNV"
#MINIO_SECRET_KEY = "minioadmin"
MINIO_SECRET_KEY = "xcrH6qANDryky8GeOHn9tArGVtR9DUuUiPO2RZ5l"
BUCKET_NAME = "users-storage"
LOG_BUCKET_NAME = "user-logs"
EVENTS_BUCKET_NAME = "events-storage"



client = Minio(
    MINIO_URL,
    access_key=MINIO_ACCESS_KEY,
    secret_key=MINIO_SECRET_KEY,
    secure=False  # Assicurati che sia False perché stai usando HTTP
)

for bucket in [BUCKET_NAME, LOG_BUCKET_NAME, EVENTS_BUCKET_NAME]:
    if not client.bucket_exists(bucket):
        client.make_bucket(bucket)

# Configura Mailjet API
MAILJET_API_KEY = os.getenv('MAILJET_API_KEY', 'a492a5597b31ff1a63558558e4e506f0')
MAILJET_SECRET_KEY = os.getenv('MAILJET_SECRET_KEY', '1f6b1c76f160bbd67ae65eed71500d18')
mailjet = Client(auth=(MAILJET_API_KEY, MAILJET_SECRET_KEY), version='v3.1')

def send_email(subject, recipient, html_content):
    data = {
        'Messages': [
            {
                "From": {
                    "Email": "noreply@yourdomain.com",
                    "Name": "Web App"
                },
                "To": [
                    {
                        "Email": recipient,
                        "Name": recipient.split("@")[0]
                    }
                ],
                "Subject": subject,
                "HTMLPart": html_content
            }
        ]
    }
    result = mailjet.send.create(data=data)
    return result.status_code, result.json()

# Configura Flask-Login
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

class User(UserMixin):
    def __init__(self, id, username, email):
        self.id = id
        self.username = username
        self.email = email

@login_manager.user_loader
def load_user(user_id):
    try:
        response = client.get_object(BUCKET_NAME, f"user_{user_id}.json")
        user_data = json.load(response)
        return User(user_id, user_data['nome'], user_data['email'])
    except Exception as e:
        print(f"Errore nel caricamento dell'utente: {e}")
        return None

def log_user_action(user_id, action):
    log_entry = {
        "user_id": user_id,
        "action": action,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    log_json = json.dumps(log_entry)
    log_file_name = f"log_{user_id}_{datetime.now(timezone.utc).timestamp()}.json"
    client.put_object(LOG_BUCKET_NAME, log_file_name, io.BytesIO(log_json.encode()), len(log_json))

class RegistrationForm(FlaskForm):
    nome = StringField('Nome', validators=[DataRequired(), Length(min=2, max=50)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    interno = StringField('Interno', validators=[DataRequired(), Regexp(r'^\d+$', message="Deve contenere solo numeri")])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Conferma Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Registrati')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Accedi')




@app.route('/')
def home():
    return render_template("home.html")

@app.route('/dashboard')
@login_required
def dashboard():
    events = [
        {"title": "Riunione condominiale", "start": "2025-02-01"},
        {"title": "Prenotazione sala comune", "start": "2025-02-05"},
        {"title": "Evento speciale", "start": "2025-02-10"}
    ]
    return render_template("dashboard.html", events=events)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data.encode('utf-8')
        try:
            response = client.get_object(BUCKET_NAME, f"user_{email}.json")
            user_data = json.load(response)
            if bcrypt.checkpw(password, user_data["password"].encode('utf-8')):
                user = User(email, user_data["nome"], user_data["email"])
                login_user(user)
                flash('Login effettuato con successo!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Credenziali errate. Riprova.', 'danger')
        except:
            flash('Utente non registrato.', 'danger')
    return render_template("login.html", form=form)



@app.route('/logout')
@login_required
def logout():
    log_user_action(current_user.id, "Logout")
    logout_user()
    flash('Logout effettuato con successo!', 'info')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        email = form.email.data
        nome = form.nome.data
        password = bcrypt.hashpw(form.password.data.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Verifica se l'email è già registrata
        try:
            client.stat_object(BUCKET_NAME, f"user_{email}.json")
            flash("L'email è già registrata. Usa un'altra email o effettua il login.", "danger")
            return redirect(url_for('register'))
        except:
            pass  # Se l'oggetto non esiste, possiamo procedere

        user_data = {"nome": nome, "email": email, "password": password}
        user_json = json.dumps(user_data)
        client.put_object(BUCKET_NAME, f"user_{email}.json", io.BytesIO(user_json.encode()), len(user_json))

        flash('Registrazione avvenuta con successo! Ora puoi effettuare il login.', 'success')
        return redirect(url_for('login'))

    return render_template("register.html", form=form)

@app.route('/debug_blob_storage')
def debug_blob_storage():
    objects = client.list_objects(BUCKET_NAME, recursive=True)
    table_data = []

    for obj in objects:
        try:
            response = client.get_object(BUCKET_NAME, obj.object_name)
            data = json.load(response)
            table_data.append({"file": obj.object_name, **data})
        except Exception as e:
            table_data.append({"file": obj.object_name, "error": str(e)})

    return render_template("debug_blob_storage.html", table_data=table_data)

@app.route('/debug_user_logs')
@login_required
def debug_user_logs():
    objects = client.list_objects(LOG_BUCKET_NAME, recursive=True)
    table_data = []

    for obj in objects:
        try:
            response = client.get_object(LOG_BUCKET_NAME, obj.object_name)
            data = json.load(response)
            table_data.append({"file": obj.object_name, **data})
        except Exception as e:
            table_data.append({"file": obj.object_name, "error": str(e)})

    return render_template("debug_user_logs.html", table_data=table_data)


@app.route('/debug_users')
@login_required
def debug_users():
    objects = client.list_objects(BUCKET_NAME, recursive=True)
    table_data = []

    for obj in objects:
        try:
            response = client.get_object(BUCKET_NAME, obj.object_name)
            data = json.load(response)
            table_data.append({"file": obj.object_name, **data})
        except Exception as e:
            table_data.append({"file": obj.object_name, "error": str(e)})

    return render_template("debug_users.html", table_data=table_data)



@app.context_processor
def inject_menu():
    return dict(menu_items=[
        {"name": "Home", "url": url_for('home')},
        {"name": "Login", "url": url_for('login')},
        {"name": "Registrati", "url": url_for('register')},
        {"name": "Dashboard", "url": url_for('dashboard') if current_user.is_authenticated else None},
        {"name": "Logout", "url": url_for('logout') if current_user.is_authenticated else None},
    ])

if __name__ == '__main__':
    app.run(debug=True)
