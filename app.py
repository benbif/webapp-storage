import os
import bcrypt
import json
import io
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_wtf import FlaskForm
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_session import Session
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from minio import Minio

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'  # Cambia questa chiave con una più sicura!
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

# Configura MinIO
MINIO_URL = "play.min.io"  # Server MinIO pubblico di test
MINIO_ACCESS_KEY = "Q3AM3UQ867SPQQA43P2F"
MINIO_SECRET_KEY = "zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG"
BUCKET_NAME = "users-storage"

client = Minio(
    MINIO_URL,
    access_key=MINIO_ACCESS_KEY,
    secret_key=MINIO_SECRET_KEY,
    secure=True
)

# Crea il bucket se non esiste
if not client.bucket_exists(BUCKET_NAME):
    client.make_bucket(BUCKET_NAME)

# Configura Flask-Mail (SMTP per l'invio delle email)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'benedetto.bifulco@gmail.com'  # Inserisci la tua email
app.config['MAIL_PASSWORD'] = 'RoccoSiffredi1'  # Usa una password per app (Gmail)
app.config['MAIL_DEFAULT_SENDER'] = 'benedetto.bifulco@gmail.com'

mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Configura Flask-Login
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

# Classe utente
class User(UserMixin):
    def __init__(self, id, username, email):
        self.id = id
        self.username = username
        self.email = email

@login_manager.user_loader
def load_user(user_id):
    try:
        data = client.get_object(BUCKET_NAME, f"user_{user_id}.json")
        user_data = json.load(data)
        return User(user_id, user_data['username'], user_data['email'])
    except:
        return None

# Form di registrazione
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Conferma Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Registrati')

# Form di login
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Accedi')

# Form di recupero password
class ResetRequestForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Invia Email')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Nuova Password', validators=[DataRequired()])
    confirm_password = PasswordField('Conferma Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Imposta Password')

@app.route('/')
def home():
    return render_template("home.html")

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        email = form.email.data
        if client.stat_object(BUCKET_NAME, f"user_{email}.json"):
            flash('Email già registrata!', 'danger')
        else:
            hashed_password = bcrypt.hashpw(form.password.data.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            user_data = {
                "username": form.username.data,
                "email": email,
                "password": hashed_password
            }
            user_json = json.dumps(user_data)
            client.put_object(BUCKET_NAME, f"user_{email}.json", io.BytesIO(user_json.encode()), len(user_json))

            flash('Registrazione completata! Ora puoi accedere.', 'success')
            return redirect(url_for('login'))
    return render_template("register.html", form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data.encode('utf-8')

        try:
            data = client.get_object(BUCKET_NAME, f"user_{email}.json")
            user_data = json.load(data)

            if bcrypt.checkpw(password, user_data["password"].encode('utf-8')):
                user = User(email, user_data["username"], user_data["email"])
                login_user(user)
                flash('Accesso riuscito! Benvenuto, ' + user.username, 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Credenziali errate!', 'danger')
        except:
            flash('Utente non registrato!', 'danger')
    
    return render_template("login.html", form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template("dashboard.html", username=current_user.username)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logout effettuato con successo.', 'success')
    return redirect(url_for('login'))

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    form = ResetRequestForm()
    if form.validate_on_submit():
        email = form.email.data

        try:
            data = client.get_object(BUCKET_NAME, f"user_{email}.json")
            user_data = json.load(data)

            token = serializer.dumps(email, salt='password-reset')
            reset_url = url_for('reset_password', token=token, _external=True)

            msg = Message('Recupero Password', recipients=[email])
            msg.body = f'Clicca sul link per reimpostare la password: {reset_url}'
            mail.send(msg)

            flash('Email di recupero inviata!', 'success')
        except:
            flash('Email non registrata.', 'danger')

    return render_template("reset_request.html", form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset', max_age=600)  # Link valido per 10 minuti
    except:
        flash('Link non valido o scaduto!', 'danger')
        return redirect(url_for('reset_request'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        new_password_hash = bcrypt.hashpw(form.password.data.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        try:
            data = client.get_object(BUCKET_NAME, f"user_{email}.json")
            user_data = json.load(data)
            user_data["password"] = new_password_hash

            client.put_object(BUCKET_NAME, f"user_{email}.json", io.BytesIO(json.dumps(user_data).encode()), len(json.dumps(user_data)))

            flash('Password aggiornata! Ora puoi accedere.', 'success')
            return redirect(url_for('login'))
        except:
            flash('Errore durante l’aggiornamento della password.', 'danger')

    return render_template("reset_password.html", form=form)

if __name__ == '__main__':
    app.run(debug=True)
