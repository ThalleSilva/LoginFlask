from flask import Flask, render_template, request, redirect, url_for
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from models import Usuario
from db import db
import hashlib

app = Flask(__name__)
app.secret_key = 'lancode'


app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///database.db"
db.init_app(app)

# Login 
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Configuração do Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.mail.yahoo.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'meuemail@yahoo.com.br'  
app.config['MAIL_PASSWORD'] = 'senhapp'    
app.config['MAIL_DEFAULT_SENDER'] = 'meuemail@yahoo.com.br' 
mail = Mail(app)

# Criador para tokens seguros
s = URLSafeTimedSerializer(app.secret_key)

def hash(txt):
    return hashlib.sha256(txt.encode('utf-8')).hexdigest()

@login_manager.user_loader
def user_loader(id):
    return Usuario.query.get(int(id))



@app.route('/incorretos', methods=['GET', 'POST'])
def incorretos():
    if request.method == 'GET':
        return render_template('incorretos.html')
    if request.method == 'POST':
        return redirect(url_for('login'))



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    acao = request.form.get('acao')

    if acao == 'log':
        nome = request.form['nomeForm']
        senha = request.form['senhaForm']
        user = Usuario.query.filter_by(nome=nome, senha=hash(senha)).first()
        if not user:
            return redirect(url_for('incorretos'))
        login_user(user)
        return redirect(url_for('home'))

    elif acao == 'cad':
        return redirect(url_for('registrar'))

    elif acao == 'rdfSenha':
        return redirect(url_for('redefinirSenha'))

@app.route('/registrar', methods=['GET', 'POST'])
def registrar():
    if request.method == 'GET':
        return render_template('registrar.html')
    nome = request.form['nomeForm']
    senha = request.form['senhaForm']
    confirmForm = request.form['confirmForm']
    email = request.form['emailForm']

    if senha != confirmForm:
        return render_template('registrar.html', erro="As senhas não conferem!")
    if Usuario.query.filter_by(nome=nome).first():
        return render_template('registrar.html', erro="Nome de usuário já existe.")
    if Usuario.query.filter_by(email=email).first():
        return render_template('registrar.html', erro="E-mail já cadastrado.")

    novo_usuario = Usuario(nome=nome, senha=hash(senha), email=email)
    db.session.add(novo_usuario)
    db.session.commit()
    login_user(novo_usuario)
    return redirect(url_for('home'))

@app.route('/', methods=['GET', 'POST'])
@login_required
def home():
    if request.method == 'GET':
        return render_template('home.html')
    acao = request.form.get('acao')
    if acao == 'logout':
        return redirect(url_for('logout'))
    elif acao == 'alterar_senha':
        return redirect(url_for('novasenha'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/sucesso', methods=['GET', 'POST'])
def sucesso():
    if request.method == 'GET':
        return render_template('sucesso.html')
    elif request.method == 'POST':
        return redirect(url_for('login'))




@app.route('/redefinirsenha', methods=['GET', 'POST'])
def redefinirSenha():
    if request.method == 'GET':
        return render_template('redefinirSenha.html')
    email = request.form['emailForm']
    user = Usuario.query.filter_by(email=email).first()
    if not user:
        return render_template('redefinirSenha.html', erro="E-mail não encontrado!")

    token = s.dumps(email, salt='redefinir-senha')
    link = url_for('novasenha_token', token=token, _external=True)

    msg = Message('Redefinição de Senha', recipients=[email])
    msg.body = f''' Olá,

Você solicitou a redefinição da sua senha.
Clique no link abaixo para criar uma nova senha (válido por 1 hora):

{link}

Se você não solicitou, ignore este e-mail.

Equipe FlaskApp'''
    mail.send(msg)

    return redirect(url_for('sucesso'))

@app.route('/sucessoSenha', methods=['GET', 'POST'])
def sucessoSenha():
    if request.method == 'GET':
        return render_template('sucessoSenha.html')
    if request.method == 'POST':
        return redirect(url_for('home'))




@app.route('/novasenha', methods=['GET', 'POST'])
def novasenha():
    if request.method == 'GET':
        return render_template('novasenha.html')

    elif request.method == 'POST':
        senha = request.form.get('senhaForm')
        confirmForm = request.form['confirmForm']


        if senha != confirmForm:
            return render_template('novasenha.html', erro="As senhas não conferem!")

        current_user.senha = hash(senha)

        db.session.commit()

        return redirect(url_for('sucessoSenha'))


@app.route('/novasenha/<token>', methods=['GET', 'POST'])
def novasenha_token(token):
    try:
        email = s.loads(token, salt='redefinir-senha', max_age=3600)
    except SignatureExpired:
        return 'O link expirou.'
    except BadSignature:
        return 'Link inválido.'

    if request.method == 'GET':
        return render_template('novasenha.html')

    senha = request.form['senhaForm']
    confirmForm = request.form['confirmForm']

    if senha != confirmForm:
        return render_template('novasenha.html', erro="As senhas não conferem!")

    user = Usuario.query.filter_by(email=email).first()
    if not user:
        return render_template('novasenha.html', erro="Usuário não encontrado!")

    user.senha = hash(senha)
    db.session.commit()
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
