from flask import Flask, render_template, request, redirect, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo
import bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'  # Cambia questa chiave!

# Dati di esempio (sostituiremo con un database in seguito)
users = {}

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
        if email in users:
            flash('Email già registrata!', 'danger')
        else:
            hashed_password = bcrypt.hashpw(form.password.data.encode('utf-8'), bcrypt.gensalt())
            users[email] = {'username': form.username.data, 'password': hashed_password}
            flash('Registrazione completata! Ora puoi accedere.', 'success')
            return redirect(url_for('login'))
    return render_template("register.html", form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data.encode('utf-8')
        if email in users and bcrypt.checkpw(password, users[email]['password']):
            flash('Accesso riuscito! Benvenuto, ' + users[email]['username'], 'success')
            return redirect(url_for('home'))
        else:
            flash('Credenziali errate!', 'danger')
    return render_template("login.html", form=form)

if __name__ == '__main__':
    app.run(debug=True)
