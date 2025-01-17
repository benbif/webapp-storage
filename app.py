import os
import bcrypt
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_wtf import FlaskForm
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo
from flask_session import Session
from minio import Minio
import json
import io

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'  # Cambia questa chiave!
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

# Configura MinIO
MINIO_URL = "play.min.io"  # Server di test pubblico
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

# Funzione per caricare l'utente dalla sessione
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

if __name__ == '__main__':
    app.run(debug=True)
