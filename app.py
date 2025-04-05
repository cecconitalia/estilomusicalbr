from flask import Flask, render_template, request, abort, url_for, redirect, session, flash, jsonify
import requests
import base64
import logging
import random
import json
from apscheduler.schedulers.background import BackgroundScheduler
from dotenv import load_dotenv
import os
from functools import wraps
import mercadopago
from sqlalchemy import and_
import time
from threading import Lock, Thread
import unicodedata
import re
import smtplib
from utils.pix import generate_valid_pix, PixError
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from sqlalchemy.exc import SQLAlchemyError
from urllib.parse import urlparse
from flask_wtf.csrf import CSRFProtect
from flask_migrate import Migrate
from flask_login import UserMixin
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.security import check_password_hash
from bs4 import BeautifulSoup
import re
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, FloatField, DateField, BooleanField, SelectField
from wtforms.validators import DataRequired, NumberRange
from flask_wtf import FlaskForm
from wtforms import StringField, DateField, SelectField
from wtforms.validators import DataRequired, Optional
from threading import Thread
from email_validator import validate_email, EmailNotValidError
from flask import Response, redirect


os.environ['FLASK_APP'] = 'app.py'

scheduler = BackgroundScheduler()


# Carregar variáveis de ambiente
load_dotenv()

app = Flask(__name__)
sdk = mercadopago.SDK("TEST-8541615133448215-032912-37f3de3b94c80d90f283e52806c292e5-251520196")  # Substitua pela sua chave
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'fallback_seguro')
csrf = CSRFProtect(app)
# Configuração do Banco de Dados
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///clientes.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)  # <--- ADICIONE ESTA LINHA AQUI
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)

# Adicione após a criação da app Flask
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

mail = Mail(app)

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    senha_hash = db.Column(db.String(128), nullable=False)
    telefone = db.Column(db.String(20))
    endereco = db.Column(db.String(200))
    bairro = db.Column(db.String(100))
    cidade = db.Column(db.String(100))
    estado = db.Column(db.String(2))
    cep = db.Column(db.String(10))
    data_nascimento = db.Column(db.Date)
    data_registro = db.Column(db.DateTime, default=datetime.utcnow)
    ativo = db.Column(db.Boolean, default=True, nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    ultimo_login = db.Column(db.DateTime)
    email_confirmado = db.Column(db.Boolean, default=False)
    avatar = db.Column(db.String(200))
    
    # Campos para sistema Prime
    prime_code = db.Column(db.String(50))
    indicador_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    desconto_prime = db.Column(db.Float, default=0.0)
    saldo_comissoes = db.Column(db.Float, default=0.0)
    
    # Relacionamentos
    indicado_por = db.relationship('User', remote_side=[id], backref='indicados')
    comissoes_recebidas = db.relationship('Comissao', foreign_keys='Comissao.indicador_id', back_populates='indicador', lazy=True)
    pedidos = db.relationship('Pedido', backref='usuario', lazy=True)

    @property
    def eh_indicador(self):
        return db.session.query(User).filter(User.indicador_id == self.id).count() > 0
    
    def set_senha(self, senha):
        self.senha_hash = generate_password_hash(senha)

    def verificar_senha(self, senha):
        return check_password_hash(self.senha_hash, senha)

    def __repr__(self):
        return f'<User {self.email}>'
    
class Comissao(db.Model):
    __tablename__ = 'comissoes'
    
    id = db.Column(db.Integer, primary_key=True)
    indicador_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    pedido_id = db.Column(db.Integer, db.ForeignKey('pedidos.id'), nullable=False)
    valor = db.Column(db.Float, nullable=False)
    percentual = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='pendente')
    data_criacao = db.Column(db.DateTime, default=datetime.utcnow)
    data_pagamento = db.Column(db.DateTime)
    
    # Modified relationships
    indicador = db.relationship('User', back_populates='comissoes_recebidas')
    pedido = db.relationship('Pedido', back_populates='comissoes')

class PerfilForm(FlaskForm):
    nome = StringField('Nome Completo', validators=[DataRequired()])
    telefone = StringField('Telefone', validators=[Optional()])
    nascimento = DateField('Data de Nascimento', validators=[Optional()], format='%Y-%m-%d')
    endereco = StringField('Endereço', validators=[Optional()])
    cep = StringField('CEP', validators=[Optional()])
    cidade = StringField('Cidade', validators=[Optional()])
    estado = SelectField('Estado', choices=[
        ('', 'Selecione...'),
        ('AC', 'AC'), ('AL', 'AL'), ('AP', 'AP'), ('AM', 'AM'),
        ('BA', 'BA'), ('CE', 'CE'), ('DF', 'DF'), ('ES', 'ES'),
        ('GO', 'GO'), ('MA', 'MA'), ('MT', 'MT'), ('MS', 'MS'),
        ('MG', 'MG'), ('PA', 'PA'), ('PB', 'PB'), ('PR', 'PR'),
        ('PE', 'PE'), ('PI', 'PI'), ('RJ', 'RJ'), ('RN', 'RN'),
        ('RS', 'RS'), ('RO', 'RO'), ('RR', 'RR'), ('SC', 'SC'),
        ('SP', 'SP'), ('SE', 'SE'), ('TO', 'TO')
    ], validators=[Optional()])
    bairro = StringField('Bairro', validators=[Optional()])

class PrimeCode(db.Model):
    __tablename__ = 'prime_codes'
    
    id = db.Column(db.Integer, primary_key=True)
    codigo = db.Column(db.String(50), unique=True, nullable=False)
    indicador_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    percentual_desconto = db.Column(db.Float, nullable=False)
    percentual_comissao = db.Column(db.Float, nullable=False)
    data_criacao = db.Column(db.DateTime, default=datetime.utcnow)
    data_expiracao = db.Column(db.DateTime)
    ativo = db.Column(db.Boolean, default=True)
    usos_maximos = db.Column(db.Integer, default=1)
    usos_atuais = db.Column(db.Integer, default=0)
    
    # Relacionamentos
    indicador = db.relationship('User', foreign_keys=[indicador_id], backref='codigos_prime')

class Pedido(db.Model):
    __tablename__ = 'pedidos'
    
    id = db.Column(db.Integer, primary_key=True)
    cliente_nome = db.Column(db.String(100), nullable=False)
    cliente_email = db.Column(db.String(100), nullable=False)
    cliente_telefone = db.Column(db.String(20), nullable=False)
    cliente_endereco = db.Column(db.String(200), nullable=False)
    total = db.Column(db.Float, nullable=False)
    total_sem_desconto = db.Column(db.Float, nullable=False)
    desconto_aplicado = db.Column(db.Float, default=0.0)
    data_pedido = db.Column(db.DateTime, default=datetime.utcnow)
    usuario_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    status = db.Column(db.String(20), default='pendente', nullable=False)
    observacoes = db.Column(db.Text, default='')  # Set default to empty string
    data_atualizacao = db.Column(db.DateTime, onupdate=datetime.utcnow)
    metodo_pagamento = db.Column(db.String(50), nullable=False)
    status_pagamento = db.Column(db.String(20), default='pendente')
    codigo_rastreio = db.Column(db.String(50))
    dados_pagamento = db.Column(db.Text)
    codigo_prime_utilizado = db.Column(db.String(50))
    valor_frete = db.Column(db.Float, default=0.0)  # Adicione este campo
    email_enviado = db.Column(db.Boolean, default=False)

    
    # Relacionamentos
    itens = db.relationship('ItemPedido', backref='pedido', lazy=True)
    comissoes = db.relationship('Comissao', back_populates='pedido', lazy=True)

class ItemPedido(db.Model):
    __tablename__ = 'itens_pedido'
    
    id = db.Column(db.Integer, primary_key=True)
    produto_codigo = db.Column(db.String(50), nullable=False)
    produto_nome = db.Column(db.String(200), nullable=False)
    quantidade = db.Column(db.Integer, nullable=False)
    preco_unitario = db.Column(db.Float, nullable=False)
    pedido_id = db.Column(db.Integer, db.ForeignKey('pedidos.id'), nullable=False)
    status = db.Column(db.String(20), default='pendente', nullable=False)

class PrimeCodeForm(FlaskForm):
    codigo = StringField('Código', validators=[DataRequired()])
    indicador_id = SelectField('Indicador', coerce=int, validators=[DataRequired()])
    percentual_desconto = FloatField('Desconto (%)', validators=[DataRequired(), NumberRange(min=0)])
    percentual_comissao = FloatField('Comissão (%)', validators=[DataRequired(), NumberRange(min=0)])
    usos_maximos = IntegerField('Usos Máximos', validators=[DataRequired(), NumberRange(min=1)])
    data_expiracao = DateField('Data de Expiração', format='%Y-%m-%d')
    ativo = BooleanField('Ativo')

def start_scheduler():
    if not scheduler.running:
        scheduler.start()


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Sistema de Autenticação
from werkzeug.security import generate_password_hash

@app.route('/admin/usuarios')
@login_required
def admin_usuarios():
    if not current_user.is_admin:
        abort(403)
    
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '').strip()
    status = request.args.get('status', 'todos')
    
    query = User.query
    
    if search:
        query = query.filter(
            (User.nome.ilike(f'%{search}%')) |
            (User.email.ilike(f'%{search}%'))
        )
    
    if status != 'todos':
        if status == 'ativos':
            query = query.filter_by(ativo=True)
        elif status == 'inativos':
            query = query.filter_by(ativo=False)
        elif status == 'admins':
            query = query.filter_by(is_admin=True)
    
    usuarios = query.order_by(User.data_registro.desc()).paginate(page=page, per_page=20)
    
    return render_template('admin_usuarios.html', usuarios=usuarios, search=search, status=status)

def enviar_email_async(app, msg, commit_pedido=False, pedido=None):
    """
    Função genérica para envio assíncrono de e-mails
    """
    def task():
        with app.app_context():
            try:
                mail.send(msg)
                if commit_pedido and pedido:
                    pedido.email_enviado = True
                    db.session.commit()
            except Exception as e:
                app.logger.error(f"Erro no envio assíncrono: {str(e)}")
                if pedido:
                    pedido.observacoes += f"\nERRO EMAIL: {str(e)}"
                    db.session.commit()

    Thread(target=task).start()


    def enviar_async(app, msg, pedido):
        with app.app_context():
            try:
                # Validação rigorosa do e-mail antes do envio
                try:
                    v = validate_email(pedido.cliente_email, check_deliverability=False)
                    email_normalizado = v.normalized
                except EmailNotValidError as e:
                    app.logger.error(f"E-mail inválido bloqueado: {pedido.cliente_email} | Erro: {str(e)}")
                    pedido.observacoes += f"\nERRO VALIDAÇÃO E-MAIL: {str(e)}"
                    db.session.commit()
                    return

                # Envio real do e-mail
                mail.send(msg)
                
                # Atualizar status e registrar sucesso
                pedido.email_enviado = True
                pedido.observacoes += f"\nE-mail enviado em: {datetime.utcnow().strftime('%d/%m/%Y %H:%M')}"
                app.logger.info(f"E-mail PARA {email_normalizado} ENVIADO COM SUCESSO - Pedido #{pedido.id}")
                
            except smtplib.SMTPException as e:
                error_msg = f"ERRO SMTP ({e.smtp_code}): {e.smtp_error.decode('utf-8')}" if hasattr(e, 'smtp_code') else f"ERRO SMTP: {str(e)}"
                app.logger.error(f"Falha no envio para {pedido.cliente_email} | {error_msg}")
                pedido.observacoes += f"\n{error_msg}"
                
            except Exception as e:
                app.logger.error(f"Erro inesperado: {str(e)}", exc_info=True)
                pedido.observacoes += f"\nERRO GERAL E-MAIL: {str(e)}"
                
            finally:
                try:
                    db.session.commit()
                except Exception as db_error:
                    app.logger.critical(f"Falha ao salvar status do e-mail: {str(db_error)}")

    try:
        # Verificação básica inicial
        if not pedido.cliente_email or '@' not in pedido.cliente_email:
            app.logger.error(f"E-mail inválido abortado: {pedido.cliente_email}")
            pedido.observacoes += "\nERRO: E-mail inválido (formato básico)"
            db.session.commit()
            return

        # Construção da mensagem
        msg = Message(
            subject=f"🎵 Estilo Musical - Pedido #{pedido.id} Confirmado",
            sender=("Estilo Musical", app.config['MAIL_USERNAME']),
            recipients=[pedido.cliente_email],
            extra_headers={
                'Reply-To': 'suporte@estilomusical.com.br',
                'X-Pedido-ID': str(pedido.id)
            }
        )

        # Adicionar versão HTML
        try:
            pix_data = generate_pix_qrcode(pedido.total, pedido.id) if pedido.metodo_pagamento == 'Pix' else None
            msg.html = render_template('email_pedido.html', 
                                     pedido=pedido,
                                     pix_data=pix_data)
        except TemplateNotFound:
            app.logger.error("Template de e-mail não encontrado!")
            msg.body = f"""
            Pedido #{pedido.id} confirmado!
            Valor total: R$ {pedido.total:.2f}
            Status: {pedido.status}
            """
        except Exception as e:
            app.logger.error(f"Erro ao renderizar template: {str(e)}")
            raise

        # Registrar tentativa antes do envio
        pedido.observacoes += f"\nTentativa de envio iniciada em: {datetime.utcnow().strftime('%d/%m/%Y %H:%M')}"
        db.session.commit()

        # Iniciar thread para envio assíncrono
        Thread(target=enviar_async, args=(app, msg, pedido)).start()

    except Exception as e:
        app.logger.error(f"Erro crítico no processo de e-mail: {str(e)}", exc_info=True)
        pedido.observacoes += f"\nERRO CRÍTICO NO PROCESSO: {str(e)}"
        db.session.commit()

def enviar_email_cliente(pedido):
    """Envia e-mail de confirmação para o cliente"""
    try:
        # ... (código existente de construção da mensagem)

        # Envio assíncrono COM commit no pedido
        enviar_email_async(app, msg, commit_pedido=True, pedido=pedido)

    except Exception as e:
        app.logger.error(f"Erro crítico: {str(e)}", exc_info=True)
        pedido.observacoes = (pedido.observacoes or "") + f"\nERRO CRÍTICO: {str(e)}"
        db.session.commit()

    def enviar_async(app, msg, pedido):
        with app.app_context():
            try:
                # Validação rigorosa do e-mail
                try:
                    v = validate_email(pedido.cliente_email, check_deliverability=True)
                    email_valido = v.normalized
                except EmailNotValidError as e:
                    app.logger.error(f"E-mail inválido: {pedido.cliente_email} | Erro: {str(e)}")
                    pedido.observacoes = (pedido.observacoes or "") + f"\nERRO VALIDAÇÃO E-MAIL: {str(e)}"
                    db.session.commit()
                    return

                # Tentativa de envio
                mail.send(msg)
                
                # Atualizar status
                pedido.email_enviado = True
                pedido.observacoes = (pedido.observacoes or "") + f"\nE-mail enviado em: {datetime.utcnow().strftime('%d/%m/%Y %H:%M')}"
                db.session.commit()
                app.logger.info(f"E-mail para {email_valido} enviado com sucesso!")

            except smtplib.SMTPResponseException as e:
                erro = f"ERRO SMTP {e.smtp_code}: {e.smtp_error.decode('utf-8')}"
                app.logger.error(f"Falha no envio: {erro}")
                pedido.observacoes = (pedido.observacoes or "") + f"\n{erro}"
                db.session.commit()

            except Exception as e:
                app.logger.error(f"Erro inesperado: {str(e)}", exc_info=True)
                pedido.observacoes = (pedido.observacoes or "") + f"\nERRO GERAL: {str(e)}"
                db.session.commit()

    try:
        # Verificação inicial do e-mail
        if not pedido.cliente_email or '@' not in pedido.cliente_email:
            app.logger.error(f"E-mail inválido: {pedido.cliente_email}")
            pedido.observacoes = (pedido.observacoes or "") + "\nERRO: E-mail inválido"
            db.session.commit()
            return

        # Construção da mensagem
        msg = Message(
            subject=f"Estilo Musical - Pedido #{pedido.id} Confirmado",
            sender=("Estilo Musical", app.config['MAIL_USERNAME']),
            recipients=[pedido.cliente_email],
            extra_headers={
                'Reply-To': 'suporte@estilomusical.com.br',
                'X-Pedido-ID': str(pedido.id)
            }
        )

        # Adicionar conteúdo HTML
        try:
            pix_data = generate_pix_qrcode(pedido.total, pedido.id) if pedido.metodo_pagamento == 'Pix' else None
            msg.html = render_template('email_pedido.html', 
                                     pedido=pedido,
                                     pix_data=pix_data)
        except TemplateNotFound:
            msg.body = f"""
            Confirmação do Pedido #{pedido.id}
            Valor Total: R$ {pedido.total:.2f}
            Status: {pedido.status}
            """
            app.logger.warning("Template de e-mail não encontrado, usando versão texto")

        # Registrar tentativa
        pedido.observacoes = (pedido.observacoes or "") + f"\nTentativa de envio em: {datetime.utcnow().strftime('%d/%m/%Y %H:%M')}"
        db.session.commit()

        # Envio assíncrono
        Thread(target=enviar_async, args=(app, msg, pedido)).start()

    except Exception as e:
        app.logger.error(f"Erro crítico: {str(e)}", exc_info=True)
        pedido.observacoes = (pedido.observacoes or "") + f"\nERRO CRÍTICO: {str(e)}"
        db.session.commit()

def calcular_frete(cep, total_pedido):
    """Calcula o valor do frete e informações adicionais"""
    if cep == '89870-000':  # CEP específico
        valor_minimo = 100.00
        valor_frete = 0.0 if total_pedido >= valor_minimo else 29.90
        return {
            'valor': valor_frete,
            'tipo': 'local',
            'valor_minimo': valor_minimo,
            'falta_para_gratis': max(0, valor_minimo - total_pedido) if total_pedido < valor_minimo else 0,
            'valor_frete_padrao': 29.90
        }
    else:  # Outros CEPs
        valor_minimo = 500.00
        valor_frete = 0.0 if total_pedido >= valor_minimo else 49.90
        return {
            'valor': valor_frete,
            'tipo': 'nacional',
            'valor_minimo': valor_minimo,
            'falta_para_gratis': max(0, valor_minimo - total_pedido) if total_pedido < valor_minimo else 0,
            'valor_frete_padrao': 49.90
        }

@app.route('/admin/prime-codes')
@login_required
def admin_prime_codes():
    if not current_user.is_admin:
        abort(403)
    
    codes = PrimeCode.query.order_by(PrimeCode.data_criacao.desc()).all()
    return render_template('admin_prime_codes.html', codes=codes)

@app.route('/admin/prime-code/novo', methods=['GET', 'POST'])
@login_required
def admin_novo_prime_code():
    if not current_user.is_admin:
        abort(403)
    
    form = PrimeCodeForm()
    form.indicador_id.choices = [(u.id, f"{u.nome} ({u.email})") for u in User.query.all()]
    
    if form.validate_on_submit():
        if PrimeCode.query.filter_by(codigo=form.codigo.data).first():
            flash('Código já existe!', 'danger')
            return redirect(url_for('admin_novo_prime_code'))
        
        novo_code = PrimeCode(
            codigo=form.codigo.data,
            indicador_id=form.indicador_id.data,
            percentual_desconto=form.percentual_desconto.data,
            percentual_comissao=form.percentual_comissao.data,
            usos_maximos=form.usos_maximos.data,
            ativo=form.ativo.data,
            data_expiracao=form.data_expiracao.data
        )
        
        db.session.add(novo_code)
        db.session.commit()
        flash('Código Prime criado com sucesso!', 'success')
        return redirect(url_for('admin_prime_codes'))
    
    return render_template('admin_novo_prime_code.html', form=form)

def calcular_total_carrinho(carrinho):
    total = sum(item['preco'] * item['quantidade'] for item in carrinho.values())
    
    # Aplicar desconto Prime
    if current_user.is_authenticated and current_user.desconto_prime > 0:
        desconto = total * (current_user.desconto_prime / 100)
        total -= desconto
    
    return total

@app.route('/criar-pagamento', methods=['POST'])
def criar_pagamento():
    # Dados do pedido (ajuste conforme seu sistema)
    data = {
        "transaction_amount": float(request.form["total"]),
        "description": f"Pedido #{request.form['pedido_id']}",
        "payment_method_id": "pix" if request.form["metodo"] == "pix" else "credit_card",
        "payer": {
            "email": request.form["email"],
            "first_name": request.form["nome"].split()[0],
        }
    }

    # Cria o pagamento
    result = sdk.payment().create(data)
    
    if result["status"] == 201:  # Pagamento criado
        if data["payment_method_id"] == "pix":
            return jsonify({
                "qr_code": result["response"]["point_of_interaction"]["transaction_data"]["qr_code"],
                "id": result["response"]["id"]
            })
        else:  # Cartão de crédito
            return jsonify({"status": "pending", "id": result["response"]["id"]})
    else:
        return jsonify({"error": result["response"]}), 400
    
@app.route('/webhook', methods=['POST'])
def webhook():
    data = request.json
    if data["action"] == "payment.updated":
        payment_id = data["data"]["id"]
        # Atualize o status do pedido no seu banco de dados
        # Ex.: Pedido.query.filter_by(mercado_pago_id=payment_id).update({"status": "aprovado"})
    return "", 200

@app.route('/admin/usuario/<int:user_id>', methods=['GET', 'POST'])
@login_required
def admin_usuario_detalhes(user_id):
    if not current_user.is_admin:
        abort(403)
    
    usuario = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        # Atualizar informações do usuário
        usuario.nome = request.form.get('nome', usuario.nome)
        usuario.email = request.form.get('email', usuario.email)
        usuario.telefone = request.form.get('telefone', usuario.telefone)
        usuario.endereco = request.form.get('endereco', usuario.endereco)
        usuario.ativo = 'ativo' in request.form
        usuario.is_admin = 'is_admin' in request.form
        
        nova_senha = request.form.get('nova_senha')
        if nova_senha:
            usuario.set_senha(nova_senha)
        
        db.session.commit()
        flash('Usuário atualizado com sucesso!', 'success')
        return redirect(url_for('admin_usuario_detalhes', user_id=user_id))
    
    return render_template('admin_usuario_detalhes.html', usuario=usuario)

@app.route('/admin/usuario/novo', methods=['GET', 'POST'])
@login_required
def admin_novo_usuario():
    if not current_user.is_admin:
        abort(403)
    
    if request.method == 'POST':
        nome = request.form['nome']
        email = request.form['email']
        senha = request.form['senha']
        is_admin = 'is_admin' in request.form
        prime_code = request.form.get('prime_code', '').strip()
        
        # Validação básica
        if User.query.filter_by(email=email).first():
            flash('Email já cadastrado!', 'danger')
            return redirect(url_for('admin_novo_usuario'))
        
        novo_usuario = User(
            nome=nome,
            email=email,
            ativo=True,
            is_admin=is_admin,
            desconto_prime=0.0,  # Valor padrão
            prime_code=prime_code if prime_code else None
        )
        
        # Validação do código Prime
        if prime_code:
            code = PrimeCode.query.filter_by(codigo=prime_code).first()
            
            if not code:
                flash('Código Prime inválido!', 'danger')
                return redirect(url_for('admin_novo_usuario'))
                
            if not code.ativo:
                flash('Código Prime desativado!', 'danger')
                return redirect(url_for('admin_novo_usuario'))
                
            if code.data_expiracao and code.data_expiracao < datetime.utcnow():
                flash('Código Prime expirado!', 'danger')
                return redirect(url_for('admin_novo_usuario'))
                
            if code.usos_atuais >= code.usos_maximos:
                flash('Código Prime já utilizado!', 'danger')
                return redirect(url_for('admin_novo_usuario'))
            
            # Aplicar benefícios
            novo_usuario.desconto_prime = code.percentual_desconto
            novo_usuario.indicador_id = code.indicador_id
            
            # Atualizar código
            code.usos_atuais += 1
            if code.usos_atuais >= code.usos_maximos:
                code.ativo = False
            db.session.add(code)
        
        novo_usuario.set_senha(senha)
        db.session.add(novo_usuario)
        
        try:
            db.session.commit()
            flash('Usuário criado com sucesso!', 'success')
            return redirect(url_for('admin_usuarios'))
        except Exception as e:
            db.session.rollback()
            flash('Erro ao criar usuário!', 'danger')
            app.logger.error(f"Erro ao criar usuário: {str(e)}")
    
    return render_template('admin_novo_usuario.html')

@app.route('/admin/usuario/<int:user_id>/excluir', methods=['POST'])
@login_required
def admin_excluir_usuario(user_id):
    if not current_user.is_admin:
        abort(403)
    
    if current_user.id == user_id:
        flash('Você não pode excluir a si mesmo!', 'danger')
        return redirect(url_for('admin_usuario_detalhes', user_id=user_id))
    
    usuario = User.query.get_or_404(user_id)
    
    # Desativa o usuário em vez de excluir para manter os pedidos associados
    usuario.ativo = False
    db.session.commit()
    
    flash('Usuário desativado com sucesso!', 'success')
    return redirect(url_for('admin_usuarios'))

@app.route('/admin/pedidos')
@login_required
def admin_pedidos():
    if not current_user.is_admin:
        abort(403)
    
    status_atual = request.args.get('status', 'todos')
    search_query = request.args.get('search', '').strip()
    page = request.args.get('page', 1, type=int)
    
    query = Pedido.query.order_by(Pedido.data_pedido.desc())
    
    if status_atual != 'todos':
        query = query.filter_by(status=status_atual)
    
    if search_query:
        query = query.filter(
            (Pedido.cliente_nome.ilike(f'%{search_query}%')) |
            (Pedido.cliente_email.ilike(f'%{search_query}%')) |
            (Pedido.id == search_query if search_query.isdigit() else False)
        )
    
    pedidos = query.paginate(page=page, per_page=20)
    
    return render_template('admin_pedidos.html', pedidos=pedidos, status_atual=status_atual)

@app.route('/admin/pedido/<int:pedido_id>')
@login_required
def admin_pedido_detalhes(pedido_id):
    if not current_user.is_admin:
        abort(403)
    
    pedido = Pedido.query.get_or_404(pedido_id)
    return render_template('admin_pedido_detalhes.html', pedido=pedido)

@app.route('/admin/pedido/<int:pedido_id>/atualizar', methods=['POST'])
@login_required
def atualizar_status_pedido(pedido_id):
    if not current_user.is_admin:
        abort(403)
    
    pedido = Pedido.query.get_or_404(pedido_id)
    status_anterior = pedido.status
    
    # Atualizar campos principais
    novo_status = request.form.get('status')
    pedido.status = novo_status
    pedido.observacoes = request.form.get('observacoes')
    pedido.codigo_rastreio = request.form.get('codigo_rastreio')
    
    # Atualizar status de todos os itens para acompanhar o status do pedido
    for item in pedido.itens:
        item.status = novo_status  # Aqui está a alteração principal
    
    db.session.commit()
    
    # Enviar e-mail apenas se o status foi alterado e não for "pendente"
    if status_anterior != novo_status and novo_status != 'pendente':
        try:
            enviar_email_status_pedido(pedido, status_anterior)
        except Exception as e:
            app.logger.error(f"Erro ao enviar e-mail de atualização: {str(e)}")
            flash('Pedido atualizado, mas ocorreu um erro ao enviar o e-mail de notificação.', 'warning')
    
    flash('Pedido atualizado com sucesso!', 'success')
    return redirect(url_for('admin_pedido_detalhes', pedido_id=pedido_id))

def enviar_email_status_pedido(pedido, status_anterior):
    """Envia e-mail de notificação quando o status do pedido é atualizado"""
    if not pedido.cliente_email or '@' not in pedido.cliente_email:
        app.logger.error(f"E-mail inválido para notificação: {pedido.cliente_email}")
        return

    # Mapeamento de status para mensagens amigáveis
    status_messages = {
        'processando': 'seu pedido está sendo processado',
        'enviado': 'seu pedido foi enviado',
        'entregue': 'seu pedido foi entregue',
        'cancelado': 'seu pedido foi cancelado'
    }
    
    assunto = f"Atualização do Pedido #{pedido.id} - {pedido.status.title()}"
    mensagem_status = status_messages.get(pedido.status, f"seu pedido foi atualizado para: {pedido.status}")
    
    # Preparar dados do template
    email_data = {
        'pedido': pedido,
        'status_anterior': status_anterior,
        'status_novo': pedido.status,
        'mensagem_status': mensagem_status,
        'data_atualizacao': datetime.utcnow().strftime('%d/%m/%Y %H:%M')
    }
    
    try:
        msg = Message(
            subject=assunto,
            sender=("Estilo Musical", app.config['MAIL_USERNAME']),
            recipients=[pedido.cliente_email],
            extra_headers={'Reply-To': 'suporte@estilomusical.com.br'}
        )
        
        msg.html = render_template('email_atualizacao_pedido.html', **email_data)
        mail.send(msg)
        
        # Registrar no pedido que o e-mail foi enviado
        pedido.observacoes = (pedido.observacoes or '') + f"\nE-mail de status {pedido.status} enviado em {datetime.utcnow().strftime('%d/%m/%Y %H:%M')}"
        db.session.commit()
        
        app.logger.info(f"E-mail de atualização enviado para {pedido.cliente_email}")
        
    except Exception as e:
        app.logger.error(f"Erro ao enviar e-mail de atualização: {str(e)}")
        pedido.observacoes = (pedido.observacoes or '') + f"\nFalha ao enviar e-mail de status: {str(e)}"
        db.session.commit()
        raise

@app.route('/admin/item/<int:item_id>/atualizar', methods=['POST'])
@login_required
def atualizar_item_pedido(item_id):
    if not current_user.is_admin:
        abort(403)
    
    item = ItemPedido.query.get_or_404(item_id)
    
    novo_status = request.form.get('status')
    nova_quantidade = int(request.form.get('quantidade', 1))
    
    item.status = novo_status
    item.quantidade = nova_quantidade
    
    # Atualizar o total do pedido
    pedido = item.pedido
    pedido.total = sum(item.quantidade * item.preco_unitario for item in pedido.itens)
    pedido.data_atualizacao = datetime.utcnow()
    
    db.session.commit()
    
    flash('Item do pedido atualizado com sucesso!', 'success')
    return redirect(url_for('admin_pedido_detalhes', pedido_id=item.pedido.id))

@app.route('/pedidos')
@login_required
def listar_pedidos():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    pedidos = Pedido.query.filter_by(usuario_id=current_user.id).order_by(Pedido.data_pedido.desc()).paginate(page=page, per_page=per_page)
    return render_template('pedidos.html', pedidos=pedidos)


@app.route('/registrar', methods=['GET', 'POST'])
def registrar():
    """Processa o registro de novos usuários"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        # Dados básicos
        nome = request.form.get('nome', '').strip()
        email = request.form.get('email', '').strip()
        senha = request.form.get('senha', '')
        confirmar_senha = request.form.get('confirmar_senha', '')
        telefone = request.form.get('telefone', '').strip()
        endereco = request.form.get('endereco', '').strip()
        numero = request.form.get('numero', '').strip()
        complemento = request.form.get('complemento', '').strip()
        cidade = request.form.get('cidade', '').strip()
        estado = request.form.get('estado', '').strip()
        cep = request.form.get('cep', '').strip()
        prime_code = request.form.get('prime_code', '').strip()

        # Montar endereço completo
        endereco_completo = f"{endereco}, {numero}" if numero else endereco
        if complemento:
            endereco_completo += f" - {complemento}"

        # Validações básicas
        if not all([nome, email, senha, confirmar_senha]):
            flash('Preencha todos os campos obrigatórios', 'warning')
            return render_template('registrar.html', 
                                 nome=nome, 
                                 email=email,
                                 telefone=telefone,
                                 endereco=endereco,
                                 numero=numero,
                                 complemento=complemento,
                                 cidade=cidade,
                                 estado=estado,
                                 cep=cep)

        if senha != confirmar_senha:
            flash('As senhas não coincidem', 'danger')
            return render_template('registrar.html', 
                                 nome=nome, 
                                 email=email,
                                 telefone=telefone,
                                 endereco=endereco,
                                 numero=numero,
                                 complemento=complemento,
                                 cidade=cidade,
                                 estado=estado,
                                 cep=cep)

        if User.query.filter_by(email=email).first():
            flash('Email já cadastrado', 'danger')
            return render_template('registrar.html', 
                                 nome=nome,
                                 telefone=telefone,
                                 endereco=endereco,
                                 numero=numero,
                                 complemento=complemento,
                                 cidade=cidade,
                                 estado=estado,
                                 cep=cep)

        # Validação do código Prime
        desconto_prime = 0.0
        indicador_id = None
        
        if prime_code:
            code = PrimeCode.query.filter_by(codigo=prime_code).first()
            
            if not code:
                flash('Código Prime inválido!', 'danger')
                return render_template('registrar.html', 
                                     nome=nome, 
                                     email=email,
                                     telefone=telefone,
                                     endereco=endereco,
                                     numero=numero,
                                     complemento=complemento,
                                     cidade=cidade,
                                     estado=estado,
                                     cep=cep)
                
            if not code.ativo:
                flash('Código Prime desativado!', 'danger')
                return render_template('registrar.html', 
                                     nome=nome, 
                                     email=email,
                                     telefone=telefone,
                                     endereco=endereco,
                                     numero=numero,
                                     complemento=complemento,
                                     cidade=cidade,
                                     estado=estado,
                                     cep=cep)
                
            if code.data_expiracao and code.data_expiracao < datetime.utcnow():
                flash('Código Prime expirado!', 'danger')
                return render_template('registrar.html', 
                                     nome=nome, 
                                     email=email,
                                     telefone=telefone,
                                     endereco=endereco,
                                     numero=numero,
                                     complemento=complemento,
                                     cidade=cidade,
                                     estado=estado,
                                     cep=cep)
                
            if code.usos_atuais >= code.usos_maximos:
                flash('Código Prime já utilizado!', 'danger')
                return render_template('registrar.html', 
                                     nome=nome, 
                                     email=email,
                                     telefone=telefone,
                                     endereco=endereco,
                                     numero=numero,
                                     complemento=complemento,
                                     cidade=cidade,
                                     estado=estado,
                                     cep=cep)
            
            # Aplicar benefícios
            desconto_prime = code.percentual_desconto
            indicador_id = code.indicador_id
            
            # Atualizar código
            code.usos_atuais += 1
            if code.usos_atuais >= code.usos_maximos:
                code.ativo = False
            db.session.add(code)

        try:
            novo_usuario = User(
                nome=nome,
                email=email,
                telefone=telefone,
                endereco=endereco_completo,
                cidade=cidade,
                estado=estado,
                cep=cep,
                desconto_prime=desconto_prime,
                indicador_id=indicador_id,
                prime_code=prime_code if prime_code else None
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
    try:
        current_user.ativo = False
        db.session.commit()
        logout_user()
        flash('Sua conta foi desativada com sucesso', 'success')
        return redirect(url_for('index'))
    except Exception as e:
        db.session.rollback()
        flash('Erro ao desativar conta', 'danger')
        app.logger.error(f"Erro ao desativar conta: {str(e)}")
        return redirect(url_for('perfil'))

@app.context_processor
def inject_cart_total():
    # Sua lógica para calcular o total de itens no carrinho
    cart_total = sum(item['quantidade'] for item in session.get('carrinho', {}).values())
    return {'cart_total_items': cart_total}

@app.route('/carrinho', methods=['GET'])
def ver_carrinho():
    carrinho = session.get('carrinho', {})
    total_sem_desconto = sum(item['preco'] * item['quantidade'] for item in carrinho.values())
    
    desconto_prime = 0.0
    if current_user.is_authenticated and hasattr(current_user, 'desconto_prime'):
        desconto_prime = total_sem_desconto * (current_user.desconto_prime / 100)
    
    total_antes_frete = total_sem_desconto - desconto_prime
    cep_cliente = current_user.cep if current_user.is_authenticated else '00000-000'
    frete_info = calcular_frete(cep_cliente, total_antes_frete)
    
    total_com_desconto = total_antes_frete + frete_info['valor']
    
    return render_template('carrinho.html',
                        carrinho=carrinho,
                        total_sem_desconto=total_sem_desconto,
                        total_com_desconto=total_com_desconto,
                        desconto_prime=desconto_prime,
                        frete_info=frete_info,
                        cart_total_items=sum(item['quantidade'] for item in carrinho.values()))

def calcular_total_carrinho(carrinho):
    total = 0
    for item in carrinho.values():
        total += item['preco'] * item['quantidade']
    return total

def limpar_descricao(html):
    """Versão mais robusta para limpeza de descrição"""
    if not html:
        return "Descrição não disponível"
    
    try:
        # Remove apenas os atributos problemáticos mantendo a estrutura
        html = re.sub(r'(style|class|box-sizing)="[^"]*"', '', html)
        # Remove divs vazias
        html = re.sub(r'<div[^>]*>(\s*|&nbsp;)*</div>', '', html)
        return html.strip()
    except Exception as e:
        app.logger.error(f"Erro ao limpar descrição: {str(e)}")
        return str(html)  # Retorna o original como fallback

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Rota de login com tratamento especial para finalização de pedidos"""
    try:
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
                
                if next_page and urlparse(next_page).path == url_for('finalizar_pedido'):
                    flash('Agora você pode finalizar seu pedido', 'success')
                    return redirect(url_for('ver_carrinho'))
                
                if usuario.is_admin:
                    return redirect(url_for('admin_dashboard'))
                    
                return redirect(next_page or url_for('index'))
            
            flash('Credenciais inválidas', 'danger')
        
        return render_template('login.html', next=request.args.get('next'))
    
    except Exception as e:
        app.logger.error(f"Erro no login: {str(e)}", exc_info=True)
        flash('Ocorreu um erro durante o login. Por favor, tente novamente.', 'danger')
        return redirect(url_for('login'))

@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        abort(403)
    
    # Existing statistics
    total_usuarios = User.query.count()
    total_pedidos = Pedido.query.count()
    pedidos_pendentes = Pedido.query.filter_by(status='pendente').count()
    
    # Today's orders
    hoje = datetime.utcnow().date()
    pedidos_hoje = Pedido.query.filter(
        db.func.date(Pedido.data_pedido) == hoje
    ).count()

    # Last orders (5 most recent)
    ultimos_pedidos = Pedido.query.order_by(
        Pedido.data_pedido.desc()
    ).limit(5).all()

    # Last registered users (5 most recent)
    ultimos_usuarios = User.query.order_by(
        User.data_registro.desc()
    ).limit(5).all()

    # Prime statistics
    codigos_ativos = PrimeCode.query.filter_by(ativo=True).count()
    codigos_expirados = PrimeCode.query.filter(
        db.and_(
            PrimeCode.data_expiracao.isnot(None),
            PrimeCode.data_expiracao < datetime.utcnow()
        )
    ).count()
    usuarios_prime = User.query.filter(User.prime_code.isnot(None)).count()
    
    # New referral and commission statistics
    total_indicacoes = User.query.filter(User.indicador_id.isnot(None)).count()
    comissoes_pagas = db.session.query(db.func.sum(Comissao.valor)).filter_by(status='pago').scalar() or 0
    comissoes_pendentes = Comissao.query.filter_by(status='pendente').count()
    
    # Top referrers (users with most referrals)
    top_indicadores = User.query.filter(
        User.indicados.any()
    ).order_by(
        db.func.coalesce(User.saldo_comissoes, 0).desc()
    ).limit(5).all()
    
    # Last commissions
    ultimas_comissoes = Comissao.query.order_by(
        Comissao.data_criacao.desc()
    ).limit(5).all()

    return render_template(
        'admin_dashboard.html',
        total_usuarios=total_usuarios,
        total_pedidos=total_pedidos,
        pedidos_pendentes=pedidos_pendentes,
        pedidos_hoje=pedidos_hoje,
        ultimos_pedidos=ultimos_pedidos,
        ultimos_usuarios=ultimos_usuarios,
        codigos_ativos=codigos_ativos,
        codigos_expirados=codigos_expirados,
        usuarios_prime=usuarios_prime,
        comissoes_pendentes=comissoes_pendentes,
        total_indicacoes=total_indicacoes,
        comissoes_pagas=comissoes_pagas,
        top_indicadores=top_indicadores,
        ultimas_comissoes=ultimas_comissoes
    )

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/pedido-sucesso/<int:pedido_id>')
@login_required
def pedido_sucesso(pedido_id):
    pedido = Pedido.query.get_or_404(pedido_id)
    
    pix_data = None
    if pedido.metodo_pagamento == 'Pix':
        try:
            pix_data = generate_valid_pix(  # Usar a função que já está importada
                amount=float(pedido.total),
                pedido_id=pedido.id
            )
        except PixError as e:
            app.logger.error(f"Erro ao gerar Pix: {str(e)}")
            flash(str(e), 'danger')
        except Exception as e:
            app.logger.error(f"Erro inesperado ao gerar Pix: {str(e)}")
            flash("Erro técnico ao gerar QR Code. Suporte já foi notificado.", 'danger')
    
    return render_template('pedido_sucesso.html', 
                         pedido=pedido,
                         pix_data=pix_data)

def generate_pix_qrcode(amount, pedido_id):
    """Gera QR Code Pix para um pedido"""
    try:
        # Implementação real usando a biblioteca PIX ou API de pagamentos
        return generate_valid_pix(amount=amount, pedido_id=pedido_id)
    except PixError as e:
        raise ValueError(f"Erro ao gerar Pix: {str(e)}")
    except Exception as e:
        raise RuntimeError(f"Erro inesperado: {str(e)}")

def enviar_notificacao_admin(pedido):
    """Envia e-mail de notificação para administradores com novo template"""
    try:
        admins = User.query.filter_by(is_admin=True).all()
        
        for admin in admins:
            try:
                # Construção da mensagem
                msg = Message(
                    subject=f"⚠️ NOVO PEDIDO #{pedido.id} - {pedido.cliente_nome}",
                    sender=("Estilo Musical", app.config['MAIL_USERNAME']),
                    recipients=[admin.email],
                    extra_headers={
                        'X-Pedido-ID': str(pedido.id),
                        'Importance': 'High'
                    }
                )
                
                msg.html = render_template(
                    'email_notificacao_admin.html',
                    pedido=pedido,
                    url_for=url_for
                )

                # Envio assíncrono SEM commit no pedido
                enviar_email_async(app, msg)
                
            except Exception as admin_error:
                app.logger.error(f"Falha ao notificar admin {admin.email}: {str(admin_error)}")

    except Exception as e:
        app.logger.error(f"Erro geral na notificação de admin: {str(e)}", exc_info=True)

@app.route('/alterar-senha', methods=['GET', 'POST'])
@login_required
def alterar_senha():
    if request.method == 'POST':
        senha_atual = request.form.get('senha_atual')
        nova_senha = request.form.get('nova_senha')
        confirmar_senha = request.form.get('confirmar_senha')
        
        if not current_user.verificar_senha(senha_atual):
            flash('Senha atual incorreta', 'danger')
            return redirect(url_for('alterar_senha'))
        
        if nova_senha != confirmar_senha:
            flash('As novas senhas não coincidem', 'danger')
            return redirect(url_for('alterar_senha'))
        
        if len(nova_senha) < 8:
            flash('A senha deve ter pelo menos 8 caracteres', 'danger')
            return redirect(url_for('alterar_senha'))
        
        try:
            current_user.set_senha(nova_senha)
            db.session.commit()
            flash('Senha alterada com sucesso!', 'success')
            return redirect(url_for('perfil'))
        except Exception as e:
            db.session.rollback()
            flash('Erro ao alterar senha. Tente novamente.', 'danger')
            app.logger.error(f"Erro ao alterar senha: {str(e)}")
    
    return render_template('alterar_senha.html')

@app.route('/perfil', methods=['GET', 'POST'])
@login_required
def perfil():
    form = PerfilForm()
    
    if request.method == 'POST' and form.validate_on_submit():
        try:
            # Atualizar os dados do usuário
            current_user.nome = form.nome.data
            current_user.telefone = form.telefone.data
            current_user.data_nascimento = form.nascimento.data
            current_user.endereco = form.endereco.data
            current_user.cep = form.cep.data
            current_user.cidade = form.cidade.data
            current_user.estado = form.estado.data
            current_user.bairro = form.bairro.data
            
            db.session.commit()
            flash('Perfil atualizado com sucesso!', 'success')
            return redirect(url_for('perfil'))
        except Exception as e:
            db.session.rollback()
            flash('Erro ao atualizar perfil: ' + str(e), 'danger')

    elif request.method == 'GET':
        # Preencher o formulário com os dados atuais
        form.nome.data = current_user.nome
        form.telefone.data = current_user.telefone
        form.nascimento.data = current_user.data_nascimento
        form.endereco.data = current_user.endereco
        form.cep.data = current_user.cep
        form.cidade.data = current_user.cidade
        form.estado.data = current_user.estado
        form.bairro.data = current_user.bairro

    # Calcular comissões se for indicador
    eh_indicador = len(current_user.indicados) > 0 or PrimeCode.query.filter_by(indicador_id=current_user.id).count() > 0
    comissao_a_receber = 0.0
    comissao_recebida = 0.0

    if eh_indicador:
        # Exemplo de cálculo - substitua com sua lógica real
        comissao_a_receber = calcular_comissao_pendente(current_user.id)
        comissao_recebida = calcular_comissao_recebida(current_user.id)

    return render_template('perfil.html',
                         user={
                             'nome': current_user.nome,
                             'email': current_user.email,
                             'telefone': current_user.telefone,
                             'data_nascimento': current_user.data_nascimento,
                             'endereco': current_user.endereco,
                             'cep': current_user.cep,
                             'cidade': current_user.cidade,
                             'estado': current_user.estado,
                             'bairro': current_user.bairro,
                             'eh_indicador': eh_indicador,
                             'comissao_a_receber': comissao_a_receber,
                             'comissao_recebida': comissao_recebida
                         },
                         form=form)

# Função para normalizar textos removendo acentos e caracteres especiais
def calcular_comissao_pendente(user_id):
    # Filtra comissões com status 'pendente'
    total = Comissao.query.filter_by(
        indicador_id=user_id,
        status='pendente'
    ).with_entities(
        db.func.sum(Comissao.valor)
    ).scalar()
    return float(total) if total else 0.0

def calcular_comissao_recebida(user_id):
    # Filtra comissões com status 'pago'
    total = Comissao.query.filter_by(
        indicador_id=user_id,
        status='pago'
    ).with_entities(
        db.func.sum(Comissao.valor)
    ).scalar()
    return float(total) if total else 0.0

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

@app.route('/indicacoes')
@login_required
def listar_indicacoes():
    # Verifica se o usuário é um indicador
    if not current_user.eh_indicador:
        abort(403)  # Acesso negado se não for indicador
    
    # Busca os usuários indicados e comissões relacionadas
    indicacoes = User.query.filter_by(indicador_id=current_user.id).all()
    comissoes = Comissao.query.filter_by(indicador_id=current_user.id).all()
    
    return render_template('indicacoes.html',
                         indicacoes=indicacoes,
                         comissoes=comissoes)

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
            seconds=3600  # Atualiza a cada 1 hora
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

    # Verificar configurações essenciais
# Verificar configurações essenciais
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
        "teclado", "pedestal", "bat", "trast", "tarr",
        "guit", "baix", "p2", "afin", "som", "baq",
        "mic", "pilha", "radio", "porta", "pen",
        "instr", "uku", "cav", "corre", "ded",
        "fone", "pele", "mesa", "palhe", "mini", "usb"
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
    try:
        produtos = get_cached_products()
        app.logger.info(f"Buscando produto com código: {codigo}")
        
        produto = next(
            (p for p in produtos 
             if p and str(p.get('codigo', '')).strip() == str(codigo).strip()),
            None
        )
        
        if not produto:
            app.logger.warning(f"Produto não encontrado: {codigo}")
            abort(404, description="Produto não encontrado")

        imagens = []
        app.logger.debug(f"Iniciando processamento de imagens para {produto['nome']}")
        app.logger.debug(f"Estrutura completa do produto: {json.dumps(produto, indent=2)}")

        # 1. Imagem principal (tratar como lista ou string)
        imagens_principal = produto.get('imagemURL', [])
        if isinstance(imagens_principal, str):
            imagens_principal = [imagens_principal]
            
        for url in imagens_principal:
            try:
                url = url.strip()
                if url and url.startswith(('http://', 'https://')):
                    imagens.append({
                        'url': url,
                        'thumb': url,
                        'tipo': 'interno'
                    })
                    app.logger.debug(f"Imagem principal adicionada: {url}")
            except Exception as e:
                app.logger.error(f"Erro em imagemURL: {str(e)}", exc_info=True)

        # 2. Processar todas as estruturas de mídia
        def processar_imagens(secao, tipo):
            if isinstance(secao, dict):
                for idx, img in enumerate(secao.get('imagens', [])):
                    try:
                        link = img.get('link', '').strip()
                        thumb = img.get('linkMiniatura', link).strip()
                        
                        if not link.startswith(('http://', 'https://')):
                            continue
                            
                        imagens.append({
                            'url': link,
                            'thumb': thumb,
                            'tipo': tipo
                        })
                        app.logger.debug(f"Imagem {tipo} {idx+1} adicionada: {link}")
                    except Exception as e:
                        app.logger.error(f"Erro em imagem {tipo} {idx+1}: {str(e)}", exc_info=True)

        # Processar mídia principal
        midia = produto.get('midia', {})
        if isinstance(midia, dict):
            processar_imagens(midia, 'interno')
            
            # Verificar subseções
            for key, subsecao in midia.items():
                if isinstance(subsecao, dict) and key != 'imagens':
                    processar_imagens(subsecao, f'interno_{key}')

        # 3. Verificar variações do produto
        for variacao in produto.get('variacoes', []):
            midia_variacao = variacao.get('midia', {})
            if isinstance(midia_variacao, dict):
                processar_imagens(midia_variacao, 'variacao')

        # 4. Remover URLs duplicados mantendo a ordem
        seen = set()
        imagens = [img for img in imagens if not (img['url'] in seen or seen.add(img['url']))]

        # 5. Fallback para imagem padrão
        if not imagens:
            default_img = url_for('static', filename='images/sem-imagem.jpg')
            imagens.append({
                'url': default_img,
                'thumb': url_for('static', filename='images/sem-imagem-thumb.jpg'),
                'tipo': 'fallback'
            })
            app.logger.warning(f"Nenhuma imagem encontrada. Usando fallback: {default_img}")

        app.logger.info(f"Total de imagens processadas para {produto['nome']}: {len(imagens)}")

        # Processar descrição
        descricao = produto.get('descricao', produto.get('descricaoCurta', 'Sem descrição disponível'))
        descricao = limpar_descricao(descricao) if descricao else 'Sem descrição disponível'

        return render_template(
            'produto.html',
            produto=produto,
            imagens=imagens,
            descricao=descricao,
            cart_total_items=sum(item['quantidade'] for item in session.get('carrinho', {}).values())
        )

    except Exception as e:
        app.logger.error(f"Erro crítico ao processar produto {codigo}: {str(e)}", exc_info=True)
        abort(500, description="Erro ao processar o produto")
        
# Adicione esta rota no app.py
@app.route('/proxy-image')
def proxy_image():
    try:
        url = request.args.get('url', '')
        app.logger.info(f"Requisição de imagem recebida: {url}")

        # Verifica se a URL é válida
        if not url or not url.startswith(('http://', 'https://')):
            return redirect(url_for('static', filename='images/sem-imagem.jpg'))

        parsed_url = urlparse(url)
        
        # Configura headers para evitar bloqueios
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Referer': f'{parsed_url.scheme}://{parsed_url.netloc}/'
        }

        # Faz a requisição com timeout
        response = requests.get(url, headers=headers, timeout=15, stream=True)
        response.raise_for_status()

        # Retorna a imagem com headers CORS
        return Response(
            response.content,
            mimetype=response.headers['Content-Type'],
            headers={
                'Cache-Control': 'public, max-age=86400',
                'Access-Control-Allow-Origin': '*'
            }
        )

    except Exception as e:
        app.logger.error(f"Falha no proxy de imagem: {str(e)}")
        return redirect(url_for('static', filename='images/sem-imagem.jpg'))
    # Rotas do Carrinho
@app.route('/adicionar-ao-carrinho', methods=['POST'])
def adicionar_ao_carrinho():
    try:
        produto_id = request.form.get('produto_id')
        quantidade = int(request.form.get('quantidade', 1))

        produto = next((p for p in get_cached_products() if str(p.get('id')) == produto_id), None)
        
        if not produto:
            return jsonify({'success': False, 'message': 'Produto não encontrado.'}), 404

        carrinho = session.get('carrinho', {})
        
        # Verificar estoque considerando itens já no carrinho
        quantidade_no_carrinho = carrinho.get(produto_id, {}).get('quantidade', 0)
        quantidade_total = quantidade_no_carrinho + quantidade
        
        estoque_disponivel = produto['estoque']['saldoVirtualTotal']
        
        if quantidade_total > estoque_disponivel:
            disponivel = max(estoque_disponivel - quantidade_no_carrinho, 0)
            return jsonify({
                'success': False,
                'message': f'Estoque insuficiente. Disponível: {disponivel}',
                'estoque_disponivel': disponivel
            }), 400

        # Atualizar carrinho
        if produto_id in carrinho:
            carrinho[produto_id]['quantidade'] += quantidade
        else:
            carrinho[produto_id] = {
                'id': produto['id'],
                'nome': produto['nome'],
                'preco': float(produto['preco']),
                'quantidade': quantidade,
                'codigo': produto['codigo'],
                'imagem': produto.get('imagemURL', ''),
                'estoque': produto['estoque']
            }

        session['carrinho'] = carrinho
        
        return jsonify({
            'success': True,
            'message': 'Produto adicionado ao carrinho!',
            'cart_total_items': sum(item['quantidade'] for item in carrinho.values()),
            'estoque_disponivel': estoque_disponivel - quantidade_total
        }), 200

    except Exception as e:
        app.logger.error(f"Erro ao adicionar produto ao carrinho: {str(e)}")
        return jsonify({'success': False, 'message': 'Erro ao processar o pedido.'}), 500
        
def calcular_total_carrinho(carrinho):
    """Calcula o total do carrinho"""
    return sum(item['preco'] * item['quantidade'] for item in carrinho.values())

@app.route('/admin/prime-code/<int:code_id>/editar', methods=['GET', 'POST'])
@login_required
def admin_editar_prime_code(code_id):
    if not current_user.is_admin:
        abort(403)
    
    code = PrimeCode.query.get_or_404(code_id)
    usuarios = User.query.all()

    if request.method == 'POST':
        code.codigo = request.form['codigo']
        code.indicador_id = request.form['indicador_id']
        code.percentual_desconto = float(request.form['percentual_desconto'])
        code.percentual_comissao = float(request.form['percentual_comissao'])
        code.usos_maximos = int(request.form['usos_maximos'])
        code.ativo = request.form.get('ativo') == 'true'
        
        expiracao = request.form.get('data_expiracao')
        code.data_expiracao = datetime.strptime(expiracao, '%Y-%m-%d') if expiracao else None
        
        db.session.commit()
        flash('Código Prime atualizado com sucesso!', 'success')
        return redirect(url_for('admin_prime_codes'))

    return render_template('admin_novo_prime_code.html', 
                         code=code, 
                         usuarios=usuarios,
                         edit_mode=True)

@app.route('/admin/prime-code/<int:code_id>/toggle', methods=['POST'])
@login_required
def admin_toggle_prime_code(code_id):
    if not current_user.is_admin:
        abort(403)
    
    code = PrimeCode.query.get_or_404(code_id)
    code.ativo = not code.ativo
    db.session.commit()
    
    flash(f'Código {code.codigo} foi {"ativado" if code.ativo else "desativado"}!', 'success')
    return redirect(url_for('admin_prime_codes'))

    
@app.route('/finalizar-pedido', methods=['POST'])
@login_required
def finalizar_pedido():
    """Finaliza o pedido com cálculo completo de frete, descontos e notificações"""
    try:
        # Verificar se o carrinho existe e não está vazio
        if 'carrinho' not in session or not session['carrinho']:
            flash('Seu carrinho está vazio', 'warning')
            return redirect(url_for('ver_carrinho'))

        metodo_pagamento = request.form.get('metodo_pagamento')
        carrinho = session['carrinho']

        # Verificação de estoque
        produtos_sem_estoque = []
        for item_id, item in carrinho.items():
            produto = next((p for p in get_cached_products() if str(p.get('id')) == item_id), None)
            if not produto or item['quantidade'] > produto['estoque']['saldoVirtualTotal']:
                produtos_sem_estoque.append(item['nome'])
        
        if produtos_sem_estoque:
            flash(f"Sem estoque suficiente para: {', '.join(produtos_sem_estoque)}", 'danger')
            return redirect(url_for('ver_carrinho'))

        # Cálculos financeiros
        total_sem_desconto = sum(float(item['preco']) * int(item['quantidade']) for item in carrinho.values())
        
        # Aplicar desconto Prime
        desconto_prime = 0.0
        if hasattr(current_user, 'desconto_prime') and current_user.desconto_prime > 0:
            desconto_prime = total_sem_desconto * (current_user.desconto_prime / 100)
        
        total_antes_frete = total_sem_desconto - desconto_prime
        
        # Cálculo do frete
        cep_cliente = current_user.cep or '00000-000'
        frete_info = calcular_frete(cep_cliente, total_antes_frete)
        valor_frete = frete_info['valor']
        
        # Total final com frete
        total_com_desconto = total_antes_frete + valor_frete

        # Criar pedido no banco de dados
        novo_pedido = Pedido(
            cliente_nome=current_user.nome,
            cliente_email=current_user.email,
            cliente_telefone=current_user.telefone or '',
            cliente_endereco=current_user.endereco or '',
            total=total_com_desconto,
            total_sem_desconto=total_sem_desconto,
            desconto_aplicado=desconto_prime,
            valor_frete=valor_frete,
            usuario_id=current_user.id,
            metodo_pagamento=metodo_pagamento,
            status_pagamento='pendente',
            status='pendente',
            codigo_prime_utilizado=current_user.prime_code if hasattr(current_user, 'prime_code') else None,
            data_pedido=datetime.utcnow()
        )
        
        db.session.add(novo_pedido)
        db.session.flush()  # Gera o ID para usar nos itens

        # Adicionar itens do pedido
        for item_id, item in carrinho.items():
            produto = next(p for p in get_cached_products() if str(p.get('id')) == item_id)
            
            db.session.add(ItemPedido(
                produto_codigo=produto['codigo'],
                produto_nome=produto['nome'],
                quantidade=item['quantidade'],
                preco_unitario=float(item['preco']),
                pedido_id=novo_pedido.id,
                status='pendente'
            ))

        # Registrar comissões para indicador Prime
        if (current_user.indicador_id and 
            current_user.desconto_prime > 0 and 
            current_user.prime_code):
            
            codigo_prime = PrimeCode.query.filter_by(codigo=current_user.prime_code).first()
            if codigo_prime and codigo_prime.percentual_comissao > 0:
                valor_comissao = total_sem_desconto * (codigo_prime.percentual_comissao / 100)
                
                nova_comissao = Comissao(
                    indicador_id=current_user.indicador_id,
                    pedido_id=novo_pedido.id,
                    valor=valor_comissao,
                    percentual=codigo_prime.percentual_comissao,
                    status='pendente',
                    data_criacao=datetime.utcnow()
                )
                db.session.add(nova_comissao)

        # Commit final de todas as alterações
        db.session.commit()

        # Enviar notificações
        enviar_notificacao_admin(novo_pedido)
        enviar_email_cliente(novo_pedido)  # Nova função de notificação por e-mail

        # Limpar carrinho e redirecionar
        session.pop('carrinho')
        return redirect(url_for('pedido_sucesso', pedido_id=novo_pedido.id))

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Erro ao finalizar pedido: {str(e)}", exc_info=True)
        flash('Erro ao processar seu pedido. Por favor, tente novamente.', 'danger')
        return redirect(url_for('ver_carrinho'))
    
@app.route('/admin/comissoes')
@login_required
def admin_comissoes():
    if not current_user.is_admin:
        abort(403)
    
    # Filtros
    status = request.args.get('status', 'todos')
    search = request.args.get('search', '').strip()
    page = request.args.get('page', 1, type=int)
    
    # Query base
    query = Comissao.query.join(User, Comissao.indicador_id == User.id)
    
    # Aplicar filtros
    if status != 'todos':
        query = query.filter(Comissao.status == status)
    
    if search:
        query = query.filter(
            (User.nome.ilike(f'%{search}%')) |
            (User.email.ilike(f'%{search}%')) |
            (Comissao.id == search if search.isdigit() else False)
        )
    
    # Ordenar e paginar
    comissoes = query.order_by(Comissao.data_criacao.desc()).paginate(page=page, per_page=20)
    
    # Estatísticas
    total_pendente = Comissao.query.filter_by(status='pendente').count()
    total_pago = Comissao.query.filter_by(status='pago').count()
    
    return render_template('admin_comissoes.html',
                         comissoes=comissoes,
                         status=status,
                         search=search,
                         total_pendente=total_pendente,
                         total_pago=total_pago)

@app.route('/admin/comissao/<int:comissao_id>/pagar', methods=['POST'])
@login_required
def admin_marcar_comissao_paga(comissao_id):
    if not current_user.is_admin:
        abort(403)
    
    comissao = Comissao.query.get_or_404(comissao_id)
    
    if comissao.status != 'pendente':
        flash('Esta comissão já foi processada', 'warning')
        return redirect(url_for('admin_comissoes'))
    
    try:
        comissao.status = 'pago'
        comissao.data_pagamento = datetime.utcnow()
        
        # Atualizar saldo do usuário (se necessário)
        usuario = comissao.indicador
        if usuario.saldo_comissoes >= comissao.valor:
            usuario.saldo_comissoes -= comissao.valor
        
        db.session.commit()
        flash('Comissão marcada como paga com sucesso!', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Erro ao pagar comissão: {str(e)}")
        flash('Erro ao processar pagamento', 'danger')
    
    return redirect(url_for('admin_comissoes'))

@app.route('/processar-cartao', methods=['GET', 'POST'])
@login_required
def processar_cartao():
    if 'carrinho' not in session or not session['carrinho']:
        flash('Seu carrinho está vazio', 'warning')
        return redirect(url_for('ver_carrinho'))
    
    total = sum(float(item['preco']) * int(item['quantidade']) for item in session['carrinho'].values())
    
    if request.method == 'POST':
        try:
            # Criar pedido primeiro
            novo_pedido = Pedido(
                cliente_nome=current_user.nome,
                cliente_email=current_user.email,
                cliente_telefone=current_user.telefone or '',
                cliente_endereco=current_user.endereco or '',
                total=total,
                usuario_id=current_user.id,
                metodo_pagamento='Cartão',
                status_pagamento='processando'
            )
            
            db.session.add(novo_pedido)
            db.session.flush()  # Gera o ID sem commit

            # Adicionar itens
            for item_id, item in session['carrinho'].items():
                produto = next(p for p in get_cached_products() if str(p.get('id')) == item_id)
                db.session.add(ItemPedido(
                    produto_codigo=produto['codigo'],
                    produto_nome=produto['nome'],
                    quantidade=item['quantidade'],
                    preco_unitario=float(item['preco']),
                    pedido_id=novo_pedido.id
                ))

            # Criar pagamento no Mercado Pago
            payment_data = {
                "transaction_amount": float(total),
                "token": request.form['token'],
                "description": f"Pedido #{novo_pedido.id}",
                "installments": int(request.form['installments']),
                "payment_method_id": request.form['payment_method_id'],
                "payer": {
                    "email": current_user.email,
                    "identification": {
                        "type": request.form['docType'],
                        "number": request.form['docNumber']
                    }
                }
            }

            payment_response = sdk.payment().create(payment_data)
            
            if payment_response['status'] in [200, 201]:
                # Pagamento criado com sucesso
                novo_pedido.status_pagamento = payment_response['response']['status']
                novo_pedido.dados_pagamento = json.dumps(payment_response['response'])
                db.session.commit()
                
                session.pop('carrinho')
                enviar_notificacao_admin(novo_pedido)
                
                return redirect(url_for('pedido_sucesso', pedido_id=novo_pedido.id))
            else:
                db.session.rollback()
                error_msg = payment_response.get('response', {}).get('message', 'Erro ao processar pagamento')
                flash(f'Erro no pagamento: {error_msg}', 'danger')
                return redirect(url_for('processar_cartao'))
                
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Erro ao processar cartão: {str(e)}", exc_info=True)
            flash('Erro ao processar seu pagamento. Por favor, tente novamente.', 'danger')
            return redirect(url_for('processar_cartao'))
    
    return render_template('processar_cartao.html', 
                         total=total,
                         public_key="TEST-8541615133448215-032912-37f3de3b94c80d90f283e52806c292e5-251520196")
    
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
