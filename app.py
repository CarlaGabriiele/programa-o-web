from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from modelos import User

app = Flask(__name__)
app.secret_key = 'chave_secreta_123'  # Para session e cookies

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# Produtos em memória
produtos = [
    {"id": 1, "nome": "Notebook", "preco": 3500},
    {"id": 2, "nome": "Mouse", "preco": 150},
    {"id": 3, "nome": "Teclado", "preco": 250},
    {"id": 4, "nome": "Monitor", "preco": 1200}
]

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

@app.route('/')
def index():
    visitas = request.cookies.get('visitas', 0)
    visitas = int(visitas) + 1

    resp = make_response(render_template('index.html'))
    resp.set_cookie('visitas', str(visitas), max_age=60*60*24)  # 1 dia
    return resp

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        senha = request.form['senha']
        hash_senha = generate_password_hash(senha)

        usuarios = session.get('usuarios', {})
        if email not in usuarios:
            usuarios[email] = hash_senha
            session['usuarios'] = usuarios

            user = User(email, hash_senha)
            login_user(user)
            session['carrinho'] = []
            flash('Cadastro realizado e login efetuado!', category='success')
            return redirect(url_for('dashboard'))
        else:
            flash('Usuário já existe!', category='error')
            return redirect(url_for('register'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Só permite login se existir pelo menos 1 usuário cadastrado
    if not session.get('usuarios'):
        flash('Nenhum usuário cadastrado. Por favor, cadastre-se primeiro.', category='error')
        return redirect(url_for('register'))

    if request.method == 'POST':
        email = request.form['email']
        senha = request.form['senha']

        usuarios = session.get('usuarios', {})
        hash_salvo = usuarios.get(email)

        if hash_salvo and check_password_hash(hash_salvo, senha):
            user = User(email, hash_salvo)
            login_user(user)
            if 'carrinho' not in session:
                session['carrinho'] = []
            flash('Login realizado com sucesso!', category='success')
            return redirect(url_for('dashboard'))
        else:
            flash('Email ou senha inválidos!', category='error')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/loja')
@login_required
def loja():
    return render_template('loja.html', produtos=produtos)

@app.route('/add_carrinho/<int:produto_id>')
@login_required
def add_carrinho(produto_id):
    if 'carrinho' not in session:
        session['carrinho'] = []

    for p in produtos:
        if p['id'] == produto_id:
            session['carrinho'].append(p)
            session.modified = True
            flash(f"{p['nome']} adicionado ao carrinho!", category='success')
            break

    return redirect(url_for('loja'))

@app.route('/carrinho')
@login_required
def carrinho():
    carrinho = session.get('carrinho', [])
    total = sum(item['preco'] for item in carrinho)
    return render_template('carrinho.html', carrinho=carrinho, total=total)

@app.route('/remover_usuario', methods=['POST'])
@login_required
def remover_usuario():
    usuarios = session.get('usuarios', {})
    if current_user.email in usuarios:
        usuarios.pop(current_user.email)
        session['usuarios'] = usuarios
        logout_user()
        flash('Conta excluída com sucesso!', category='success')
    return redirect(url_for('index'))

@app.route('/remover_item_carrinho/<int:index>')
@login_required
def remover_item_carrinho(index):
    carrinho = session.get('carrinho', [])
    if 0 <= index < len(carrinho):
        item_removido = carrinho.pop(index)
        session['carrinho'] = carrinho
        session.modified = True
        flash(f"{item_removido['nome']} removido do carrinho!", category='success')
    else:
        flash("Item inválido!", category='error')
    return redirect(url_for('carrinho'))

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    flash('Logout realizado com sucesso!', category='success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
