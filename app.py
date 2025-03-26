from flask import Flask, render_template, request, abort, url_for, redirect, session, flash, jsonify
import requests
import base64
import logging
import random
from apscheduler.schedulers.background import BackgroundScheduler
from dotenv import load_dotenv
import os
from functools import wraps
import time
from threading import Lock, Thread
import unicodedata
import re
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from sqlalchemy.exc import SQLAlchemyError
from urllib.parse import urlparse
from flask_wtf.csrf import CSRFProtect
from flask_migrate import Migrate
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.security import check_password_hash

scheduler = BackgroundScheduler()


# Carregar variáveis de ambiente
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'fallback_seguro')
csrf = CSRFProtect(app)

# Configuração do Banco de Dados
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///clientes.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)  # <--- ADICIONE ESTA LINHA AQUI
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
migrate = Migrate(app, db)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    senha_hash = db.Column(db.String(128), nullable=False)
    telefone = db.Column(db.String(20))
    endereco = db.Column(db.String(200))
    cidade = db.Column(db.String(100))
    estado = db.Column(db.String(2))
    cep = db.Column(db.String(10))
    data_registro = db.Column(db.DateTime, default=datetime.utcnow)

    def set_senha(self, senha):
        self.senha_hash = generate_password_hash(senha)

    def verificar_senha(self, senha):
        return check_password_hash(self.senha_hash, senha)

# Modelo de Pedido
class Pedido(db.Model):
    # Mantenha apenas os campos necessários para armazenamento local
    id = db.Column(db.Integer, primary_key=True)
    cliente_nome = db.Column(db.String(100), nullable=False)
    cliente_email = db.Column(db.String(100), nullable=False)
    cliente_telefone = db.Column(db.String(20), nullable=False)
    cliente_endereco = db.Column(db.String(200), nullable=False)
    total = db.Column(db.Float, nullable=False)
    data_pedido = db.Column(db.DateTime, default=datetime.utcnow)
    usuario_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    itens = db.relationship('ItemPedido', backref='pedido', lazy=True)

class ItemPedido(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    produto_codigo = db.Column(db.String(50), nullable=False)
    produto_nome = db.Column(db.String(200), nullable=False)
    quantidade = db.Column(db.Integer, nullable=False)
    preco_unitario = db.Column(db.Float, nullable=False)
    pedido_id = db.Column(db.Integer, db.ForeignKey('pedido.id'), nullable=False)

def start_scheduler():
    if not scheduler.running:
        scheduler.start()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Sistema de Autenticação
from werkzeug.security import generate_password_hash

@app.route('/pedidos')
@login_required
def listar_pedidos():
    """Lista todos os pedidos do sistema"""
    # Verificar se é admin (adicione um campo is_admin na model User se necessário)
    # if not current_user.is_admin:
    #     abort(403)
    
    pedidos = Pedido.query.order_by(Pedido.data_pedido.desc()).all()
    return render_template('pedidos.html', pedidos=pedidos)

@app.route('/registrar', methods=['GET', 'POST'])
def registrar():
    """Processa o registro de novos usuários"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        nome = request.form.get('nome', '').strip()
        email = request.form.get('email', '').strip()
        senha = request.form.get('senha', '')
        confirmar_senha = request.form.get('confirmar_senha', '')
        telefone = request.form.get('telefone', '').strip()
        endereco = request.form.get('endereco', '').strip()
        cidade = request.form.get('cidade', '').strip()
        estado = request.form.get('estado', '').strip()
        cep = request.form.get('cep', '').strip()

        # Validações
        if not all([nome, email, senha, confirmar_senha]):
            flash('Preencha todos os campos obrigatórios', 'warning')
            return render_template('registrar.html', nome=nome, email=email)

        if senha != confirmar_senha:
            flash('As senhas não coincidem', 'danger')
            return render_template('registrar.html', nome=nome, email=email)

        if User.query.filter_by(email=email).first():
            flash('Email já cadastrado', 'danger')
            return render_template('registrar.html', nome=nome)

        try:
            novo_usuario = User(
                nome=nome,
                email=email,
                telefone=telefone,
                endereco=endereco,
                cidade=cidade,
                estado=estado,
                cep=cep
            )
            novo_usuario.set_senha(senha)
            db.session.add(novo_usuario)
            db.session.commit()
            
            login_user(novo_usuario)
            next_page = request.args.get('next', url_for('ver_carrinho' if session.get('carrinho') else 'index'))
            
            flash('Cadastro realizado com sucesso!', 'success')
            return redirect(next_page)

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Erro no registro: {str(e)}")
            flash('Erro ao cadastrar. Tente novamente.', 'danger')

    return render_template('registrar.html', next=request.args.get('next'))

@app.route('/excluir-conta', methods=['POST'])
@login_required
def excluir_conta():
    # Lógica para excluir a conta do usuário
    try:
        # Exemplo básico - adapte para seu sistema
        db.session.delete(current_user)
        db.session.commit()
        logout_user()
        flash('Sua conta foi excluída com sucesso.', 'success')
        return redirect(url_for('index'))
    except Exception as e:
        db.session.rollback()
        flash('Ocorreu um erro ao excluir sua conta.', 'danger')
        return redirect(url_for('perfil'))

@app.context_processor
def inject_cart_total():
    # Sua lógica para calcular o total de itens no carrinho
    cart_total = sum(item['quantidade'] for item in session.get('carrinho', {}).values())
    return {'cart_total_items': cart_total}

@app.route('/carrinho', methods=['GET'])
def ver_carrinho():
    """Rota para visualizar o carrinho"""
    carrinho = session.get('carrinho', {})
    total = sum(item['preco'] * item['quantidade'] for item in carrinho.values())
    
    # Verifica se veio do login para mostrar mensagem
    from_login = request.args.get('from_login') == '1'
    if from_login:
        flash('Agora você pode finalizar seu pedido', 'info')
    
    return render_template('carrinho.html',
                        carrinho=carrinho,
                        total=total,
                        cart_total_items=sum(item['quantidade'] for item in carrinho.values()))

def calcular_total_carrinho(carrinho):
    total = 0
    for item in carrinho.values():
        total += item['preco'] * item['quantidade']
    return total

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Rota de login com tratamento especial para finalização de pedidos"""
    if current_user.is_authenticated:
        flash('Você já está logado', 'info')
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        senha = request.form.get('senha', '')
        remember = request.form.get('remember') == 'on'

        if not email or not senha:
            flash('Preencha todos os campos', 'warning')
            return render_template('login.html', email=email)

        usuario = User.query.filter_by(email=email).first()

        if usuario and usuario.verificar_senha(senha):
            login_user(usuario, remember=remember)
            
            next_page = request.args.get('next')
            
            # Tratamento especial para fluxo de finalização
            if next_page and urlparse(next_page).path == url_for('finalizar_pedido'):
                flash('Agora você pode finalizar seu pedido', 'success')
                return redirect(url_for('ver_carrinho'))
                
            return redirect(next_page or url_for('index'))
        
        flash('Credenciais inválidas', 'danger')
    
    return render_template('login.html', next=request.args.get('next'))

    
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/pedido-sucesso/<int:pedido_id>')
@login_required
def pedido_sucesso(pedido_id):
    """Exibe a página de confirmação do pedido"""
    pedido = Pedido.query.get_or_404(pedido_id)
    return render_template('pedido_sucesso.html', pedido=pedido)

@app.route('/perfil', methods=['GET', 'POST'])
@login_required
def perfil():
    if request.method == 'POST':
        # Atualizar informações do perfil
        current_user.nome = request.form.get('nome', current_user.nome)
        current_user.telefone = request.form.get('telefone', current_user.telefone)
        current_user.endereco = request.form.get('endereco', current_user.endereco)
        current_user.cidade = request.form.get('cidade', current_user.cidade)
        current_user.estado = request.form.get('estado', current_user.estado)
        current_user.cep = request.form.get('cep', current_user.cep)
        
        # Verificar se a senha foi alterada
        nova_senha = request.form.get('nova_senha')
        if nova_senha:
            current_user.set_senha(nova_senha)
        
        try:
            db.session.commit()
            flash('Perfil atualizado com sucesso!', 'success')
        except Exception as e:
            db.session.rollback()
            flash('Erro ao atualizar perfil. Tente novamente.', 'danger')
            app.logger.error(f"Erro ao atualizar perfil: {str(e)}")
        
        return redirect(url_for('perfil'))

    # Buscar pedidos do usuário logado
    pedidos = Pedido.query.filter_by(usuario_id=current_user.id).order_by(Pedido.data_pedido.desc()).all()
    return render_template('perfil.html', user=current_user, pedidos=pedidos)

# Função para normalizar textos removendo acentos e caracteres especiais
def normalize_text(text):
    text = unicodedata.normalize('NFD', text)
    text = ''.join(c for c in text if not unicodedata.combining(c))
    text = text.lower()
    text = re.sub(r'[^a-z0-9\s]', '', text)
    return text

# Funções para contagem de acessos
ACCESS_FILE = 'access_count.txt'

@app.before_request
def proteger_sessao():
    """Garante que a sessão do carrinho exista"""
    session.modified = True
    if 'carrinho' not in session:
        session['carrinho'] = {}

def get_access_count():
    if os.path.exists(ACCESS_FILE):
        with open(ACCESS_FILE, 'r') as file:
            return int(file.read())
    return 0

def increment_access_count():
    count = get_access_count() + 1
    with open(ACCESS_FILE, 'w') as file:
        file.write(str(count))

@app.route('/remover-do-carrinho/<produto_id>', methods=['POST'])
def remover_do_carrinho(produto_id):
    carrinho = session.get('carrinho', {})
    if produto_id in carrinho:
        del carrinho[produto_id]
        session['carrinho'] = carrinho
        flash('Item removido do carrinho!', 'success')
    else:
        flash('Item não encontrado no carrinho.', 'warning')
    return redirect(url_for('ver_carrinho'))

@app.route('/acessos')
def acessos():
    increment_access_count()
    count = get_access_count()
    return render_template('acessos.html', numero_de_acessos=count)

# Verificação de variáveis de ambiente obrigatórias para integração com o Bling
client_id = os.getenv('BLING_CLIENT_ID')
client_secret = os.getenv('BLING_CLIENT_SECRET')
required_env_vars = ['BLING_CLIENT_ID', 'BLING_CLIENT_SECRET', 'ACCESS_TOKEN', 'REFRESH_TOKEN']
missing_vars = [var for var in required_env_vars if not os.getenv(var)]
if missing_vars:
    raise EnvironmentError(f"Variáveis de ambiente faltando: {', '.join(missing_vars)}")

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Classe para integrar com a API do Bling
class BlingAPI:
    def __init__(self):
        self.client_id = client_id
        self.client_secret = client_secret
        self.refresh_token = os.getenv('REFRESH_TOKEN')
        self.access_token = os.getenv('ACCESS_TOKEN')
        self.base_url = "https://api.bling.com.br/Api/v3"
        self.session = requests.Session()
        self.scheduler = BackgroundScheduler()
        self._setup_token_refresh_scheduler()
        if not self.access_token:
            raise EnvironmentError("ACCESS_TOKEN não encontrado. Execute o fluxo de autorização.")
        self.PRODUTOS_POR_PAGINA_API = 100
        self.MAX_PAGES = 50  # Limita o número máximo de páginas para evitar loops infinitos
        self.last_token_refresh_time = time.time()  # Armazena o momento da última atualização

    def _setup_token_refresh_scheduler(self):
        self.scheduler.add_job(
            func=self._refresh_access_token,
            trigger='interval',
            seconds=7200  # Atualiza a cada 2 horas
        )
        self.scheduler.start()

    def _refresh_access_token(self):
        try:
            auth_string = f"{self.client_id}:{self.client_secret}"
            encoded_auth = base64.b64encode(auth_string.encode()).decode()
            
            headers = {
                'Authorization': f'Basic {encoded_auth}',
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            data = {
                'grant_type': 'refresh_token',
                'refresh_token': self.refresh_token
            }
            
            response = self.session.post(
                f"{self.base_url}/oauth/token",
                headers=headers,
                data=data,
                timeout=10
            )
            response.raise_for_status()
            
            tokens = response.json()
            self.access_token = tokens['access_token']
            self.refresh_token = tokens['refresh_token']
            self.last_token_refresh_time = time.time()  # Atualiza o horário do refresh
            logger.info("Tokens atualizados com sucesso")
            
            # Atualiza as variáveis de ambiente e o arquivo .env (não recomendado para produção)
            os.environ['ACCESS_TOKEN'] = self.access_token
            os.environ['REFRESH_TOKEN'] = self.refresh_token
            with open('.env', 'w') as env_file:
                env_file.write(f"BLING_CLIENT_ID={os.getenv('BLING_CLIENT_ID')}\n")
                env_file.write(f"BLING_CLIENT_SECRET={os.getenv('BLING_CLIENT_SECRET')}\n")
                env_file.write(f"ACCESS_TOKEN={self.access_token}\n")
                env_file.write(f"REFRESH_TOKEN={self.refresh_token}\n")
            
        except Exception as e:
            logger.error(f"Falha ao atualizar tokens: {str(e)}")

    def check_and_refresh_token(self):
        if time.time() - self.last_token_refresh_time > 7100:
            logger.info("Token expirado pelo tempo, atualizando...")
            self._refresh_access_token()

    def get_all_products(self):
        self.check_and_refresh_token()

        all_products = []
        page = 1
        
        while page <= self.MAX_PAGES:
            try:
                headers = {
                    'Authorization': f'Bearer {self.access_token}',
                    'Accept': 'application/json'
                }
                
                params = {
                    'pagina': page,
                    'limite': self.PRODUTOS_POR_PAGINA_API
                }
                
                response = self.session.get(
                    f"{self.base_url}/produtos",
                    headers=headers,
                    params=params,
                    timeout=15
                )
                
                if response.status_code == 401:
                    logger.info("Token expirado, atualizando...")
                    self._refresh_access_token()
                    continue  # Tenta novamente após atualizar o token
                
                response.raise_for_status()
                
                data = response.json()
                products = data.get('data', [])
                
                if not products:
                    break
       
                all_products.extend(products)
                
                if len(products) < self.PRODUTOS_POR_PAGINA_API:
                    break
                
                page += 1
                
            except requests.exceptions.RequestException as e:
                logger.error(f"Falha na requisição da API: {str(e)}")
                break

        return all_products

# Inicializa a API Bling
bling_api = BlingAPI()

# Cache de produtos
cached_products = []
cache_timestamp = 0
CACHE_DURATION = 600  # 10 minutos em segundos
cache_lock = Lock()

def update_product_cache():
    global cached_products, cache_timestamp
    try:
        products = bling_api.get_all_products()
        with cache_lock:
            cached_products = products
            cache_timestamp = time.time()
        logger.info("Cache de produtos atualizado com sucesso.")
    except Exception as e:
        logger.error(f"Erro ao atualizar o cache de produtos: {str(e)}")

def get_cached_products():
    global cached_products, cache_timestamp
    with cache_lock:
        is_expired = (time.time() - cache_timestamp > CACHE_DURATION)
        current_cache = cached_products.copy()
    if current_cache and is_expired:
        logger.info("Cache expirado. Atualizando cache em background...")
        Thread(target=update_product_cache).start()
        return current_cache
    elif not current_cache:
        logger.info("Cache vazio. Atualizando cache de forma síncrona...")
        update_product_cache()
        with cache_lock:
            return cached_products
    return current_cache

# Agendador para atualizar o cache de produtos a cada 10 minutos
product_scheduler = BackgroundScheduler()
product_scheduler.add_job(update_product_cache, 'interval', seconds=CACHE_DURATION)
product_scheduler.start()

# Rota para callback de autorização
@app.route('/callback')
def callback():
    code = request.args.get('code')
    if not code:
        return "Erro: código de autorização não encontrado."
    
    token_url = 'https://www.bling.com.br/Api/v3/oauth/token'
    credentials = f'{client_id}:{client_secret}'
    credentials_base64 = base64.b64encode(credentials.encode()).decode('utf-8')

    headers = {
        'Authorization': f'Basic {credentials_base64}',
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    data = {
        'grant_type': 'authorization_code',
        'code': code
    }

    response = requests.post(token_url, headers=headers, data=data)
    
    if response.status_code == 200:
        tokens = response.json()
        access_token = tokens.get('access_token')
        refresh_token = tokens.get('refresh_token')

        with open('.env', 'a') as env_file:
            env_file.write(f'ACCESS_TOKEN={access_token}\n')
            env_file.write(f'REFRESH_TOKEN={refresh_token}\n')

        os.environ['ACCESS_TOKEN'] = access_token
        os.environ['REFRESH_TOKEN'] = refresh_token

        return "Tokens obtidos e armazenados com sucesso!"
    else:
        return f"Erro ao obter tokens: {response.text}"

# Filtro de template para formatação em BRL
@app.template_filter('brl')
def format_brl(value):
    try:
        # Converter para float antes de formatar
        return f'R$ {float(value):,.2f}'.replace(',', 'v').replace('.', ',').replace('v', '.')
    except (ValueError, TypeError):
        return 'R$ 0,00'

# Decorador para tratamento de erros na API
def handle_api_errors(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except RuntimeError as e:
            logger.error(f"Erro na API: {str(e)}")
            return render_template('error.html', message="Serviço temporariamente indisponível"), 503
        except Exception as e:
            logger.error(f"Erro inesperado: {str(e)}")
            return render_template('error.html', message="Ocorreu um erro inesperado"), 500
    return wrapper

# Rota principal (catálogo de produtos)
@app.route('/')
@handle_api_errors
def index():
    search_query = request.args.get('search', '').strip()
    normalized_search = normalize_text(search_query) if search_query else ''

    palavras = [
        "viol", "cord", "p10", "xlr", "pandeiro",
        "teclado", "pedestal", "bat", "cap", "tarr",
        "guit", "baix", "p2", "afin", "som", "baq",
        "mic", "pilha", "radio", "porta", "pen", "amp",
        "instr", "amp", "uku", "cav", "corre", "ded",
        "fone", "pele", "mesa", "palhe", "mini", "amp"
    ]

    produtos = get_cached_products()

    produtos_filtrados = []
    for produto in produtos:
        nome = normalize_text(produto.get('nome', ''))
        try:
            estoque = float(produto.get('estoque', {}).get('saldoVirtualTotal', 0))
        except (ValueError, TypeError):
            estoque = 0
        if any(palavra in nome for palavra in palavras) and estoque > 0:
            produtos_filtrados.append(produto)

    produtos_ordenados = sorted(produtos_filtrados, key=lambda p: normalize_text(p.get('nome', '')))

    message = None
    if normalized_search:
        query_tokens = normalized_search.split()
        produtos_busca = [
            produto for produto in produtos_ordenados
            if any(token in normalize_text(produto.get('nome', '')) for token in query_tokens)
        ]
        if not produtos_busca:
            message = f"Nenhum produto encontrado para '{search_query}'."
        else:
            def product_score(prod):
                nome_normalizado = normalize_text(prod.get('nome', ''))
                score = sum(1 for token in query_tokens if token in nome_normalizado)
                positions = [nome_normalizado.find(token) for token in query_tokens if token in nome_normalizado]
                min_pos = min(positions) if positions else float('inf')
                return (score, -min_pos)
            produtos_busca = sorted(produtos_busca, key=product_score, reverse=True)
        produtos_ordenados = produtos_busca
    else:
        random.shuffle(produtos_ordenados)

    produtos_por_pagina_ui = 30
    pagina = request.args.get('pagina', 1, type=int)
    total_produtos = len(produtos_ordenados)
    total_paginas = (total_produtos + produtos_por_pagina_ui - 1) // produtos_por_pagina_ui

    inicio = (pagina - 1) * produtos_por_pagina_ui
    fim = inicio + produtos_por_pagina_ui
    produtos_pagina = produtos_ordenados[inicio:fim]

    return render_template(
        'catalogo.html',
        produtos=produtos_pagina,
        pagina=pagina,
        total_paginas=total_paginas,
        message=message,
    )

def obter_estoque_produto(produto_id):
    """
    Retorna o estoque disponível de um produto com base no ID.
    """
    produtos = get_cached_products()  # Supondo que você tenha uma função para obter os produtos
    produto = next((p for p in produtos if str(p.get('id')) == produto_id), None)
    return produto['estoque']['saldoVirtualTotal'] if produto else 0

# Adicionar a função ao contexto do Jinja2
@app.context_processor
def inject_obter_estoque_produto():
    return {'obter_estoque_produto': obter_estoque_produto}

# Rota para detalhe do produto

@app.route('/produto/<codigo>')
def product_detail(codigo):
    produtos = get_cached_products()
    produto = next((p for p in produtos if p.get('codigo') == codigo), None)
    
    if not produto:
        abort(404, description="Produto não encontrado")
        
    return render_template('produto.html', produto=produto)

# Rotas do Carrinho
@app.route('/adicionar-ao-carrinho', methods=['POST'])
def adicionar_ao_carrinho():
    try:
        produto_id = request.form.get('produto_id')
        quantidade = int(request.form.get('quantidade', 1))

        if not produto_id:
            return jsonify({'success': False, 'message': 'ID do produto não fornecido.'}), 400

        # Buscar o produto no cache ou banco de dados
        produto = next((p for p in get_cached_products() if str(p.get('id')) == produto_id), None)

        if not produto:
            return jsonify({'success': False, 'message': 'Produto não encontrado.'}), 404

        # Verificar se a quantidade solicitada excede o estoque
        if quantidade > produto['estoque']['saldoVirtualTotal']:
            return jsonify({'success': False, 'message': 'Quantidade solicitada excede o estoque disponível.'}), 400

        # Adicionar ao carrinho na sessão
        carrinho = session.get('carrinho', {})
        if produto_id in carrinho:
            # Verificar se a nova quantidade excede o estoque
            nova_quantidade = carrinho[produto_id]['quantidade'] + quantidade
            if nova_quantidade > produto['estoque']['saldoVirtualTotal']:
                return jsonify({'success': False, 'message': 'Quantidade solicitada excede o estoque disponível.'}), 400
            carrinho[produto_id]['quantidade'] = nova_quantidade
        else:
            carrinho[produto_id] = {
                'id': produto['id'],
                'nome': produto['nome'],
                'preco': float(produto['preco']),
                'quantidade': quantidade,
                'codigo': produto['codigo'],
                'estoque': produto['estoque']  # Adicionar o estoque ao item do carrinho
            }

        session['carrinho'] = carrinho
        return jsonify({
            'success': True,
            'message': 'Produto adicionado ao carrinho!',
            'cart_total_items': sum(item['quantidade'] for item in carrinho.values())
        }), 200

    except Exception as e:
        app.logger.error(f"Erro ao adicionar produto ao carrinho: {str(e)}")
        return jsonify({'success': False, 'message': 'Ocorreu um erro ao adicionar o produto ao carrinho.'}), 500

        
def calcular_total_carrinho(carrinho):
    """Calcula o total do carrinho"""
    return sum(item['preco'] * item['quantidade'] for item in carrinho.values())
    
@app.route('/finalizar-pedido', methods=['POST'])
@login_required
def finalizar_pedido():
    """
    Rota para finalização de pedidos
    Requer autenticação e método POST
    """
    try:
        # Verifica se o carrinho existe e não está vazio
        if 'carrinho' not in session or not session['carrinho']:
            flash('Seu carrinho está vazio', 'warning')
            return redirect(url_for('ver_carrinho'))

        # Verifica estoque antes de processar
        produtos_com_estoque_insuficiente = []
        for item_id, item in session['carrinho'].items():
            produto = next((p for p in get_cached_products() if str(p['id']) == item_id), None)
            if not produto or item['quantidade'] > produto['estoque']['saldoVirtualTotal']:
                produtos_com_estoque_insuficiente.append(item['nome'])

        if produtos_com_estoque_insuficiente:
            flash(f"Estoque insuficiente para: {', '.join(produtos_com_estoque_insuficiente)}", 'danger')
            return redirect(url_for('ver_carrinho'))

        # Cria o pedido no banco de dados
        novo_pedido = Pedido(
            cliente_nome=current_user.nome,
            cliente_email=current_user.email,
            cliente_telefone=request.form.get('telefone', ''),
            cliente_endereco=request.form.get('endereco', ''),
            total=sum(float(item['preco']) * int(item['quantidade']) for item in session['carrinho'].values()),
            usuario_id=current_user.id
        )
        db.session.add(novo_pedido)
        db.session.flush()  # Para obter o ID do pedido

        # Adiciona os itens do pedido
        for item_id, item in session['carrinho'].items():
            produto = next(p for p in get_cached_products() if str(p['id']) == item_id)
            
            novo_item = ItemPedido(
                produto_codigo=produto['codigo'],
                produto_nome=produto['nome'],
                quantidade=item['quantidade'],
                preco_unitario=float(item['preco']),
                pedido_id=novo_pedido.id
            )
            db.session.add(novo_item)

        # Finaliza a transação
        db.session.commit()
        
        # Limpa o carrinho e prepara resposta
        session.pop('carrinho')
        
        # Registra conversão para Google Ads (opcional)
        if os.environ.get('FLASK_ENV') == 'production':
            gtag('event', 'conversion', {
                'send_to': 'AW-XXXXXX/YYYYYYYY',
                'value': novo_pedido.total,
                'currency': 'BRL',
                'transaction_id': novo_pedido.id
            })

        return redirect(url_for('pedido_sucesso', pedido_id=novo_pedido.id))

    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Erro no banco de dados ao finalizar pedido: {str(e)}")
        flash('Erro ao processar seu pedido. Por favor, tente novamente.', 'danger')
        return redirect(url_for('ver_carrinho'))

    except Exception as e:
        app.logger.error(f"Erro inesperado ao finalizar pedido: {str(e)}")
        flash('Ocorreu um erro inesperado. Nossa equipe já foi notificada.', 'danger')
        return redirect(url_for('ver_carrinho'))
    
@app.route('/atualizar-quantidade/<produto_id>', methods=['POST'])
def atualizar_quantidade(produto_id):
    try:
        nova_quantidade = int(request.form.get('quantidade', 1))
        carrinho = session.get('carrinho', {})

        if produto_id in carrinho:
            # Verificar se a nova quantidade é válida
            if nova_quantidade < 1:
                return jsonify({'success': False, 'message': 'A quantidade deve ser pelo menos 1.'}), 400

            # Verificar se a nova quantidade não excede o estoque
            produto = next((p for p in get_cached_products() if str(p.get('id')) == produto_id), None)
            if produto and nova_quantidade > produto['estoque']['saldoVirtualTotal']:
                return jsonify({'success': False, 'message': 'Quantidade solicitada excede o estoque disponível.'}), 400

            # Atualizar a quantidade no carrinho
            carrinho[produto_id]['quantidade'] = nova_quantidade
            session['carrinho'] = carrinho

            return jsonify({
                'success': True,
                'message': 'Quantidade atualizada!',
                'cart_total_items': sum(item['quantidade'] for item in carrinho.values())
            }), 200
        else:
            return jsonify({'success': False, 'message': 'Produto não encontrado no carrinho.'}), 404

    except Exception as e:
        app.logger.error(f"Erro ao atualizar quantidade: {str(e)}")
        return jsonify({'success': False, 'message': 'Ocorreu um erro ao atualizar a quantidade.'}), 500

# Configurações adicionais para ambiente de desenvolvimento
if os.getenv('FLASK_ENV') == 'development':
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
    app.jinja_env.auto_reload = True
    logging.basicConfig(level=logging.DEBUG)

# Inicialização do aplicativo
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)