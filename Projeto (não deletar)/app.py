import os
import datetime
import secrets
import time
import sqlite3
import jwt
from functools import wraps
from flask import Flask, request, jsonify, render_template_string, redirect, url_for, session, g
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'hotel.db')
JWT_SECRET_FILE = os.path.join(BASE_DIR, '.jwt_secret')
TEMPLATES_DIR = BASE_DIR

app = Flask(
    __name__,
    template_folder=TEMPLATES_DIR
)

def get_or_create_secret(env_name, file_path=None):
    value = os.getenv(env_name, '').strip()
    if value:
        return value
    if file_path and os.path.exists(file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                value = f.read().strip()
                if value:
                    return value
        except Exception:
            pass
    value = secrets.token_urlsafe(48)
    if file_path:
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(value)
        except Exception:
            pass
    return value

app.config['SECRET_KEY'] = get_or_create_secret('FLASK_SECRET_KEY', JWT_SECRET_FILE)
JWT_SECRET = get_or_create_secret('JWT_SECRET', JWT_SECRET_FILE)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.getenv('SESSION_COOKIE_SECURE', '0').lower() in ('1', 'true', 'yes'),
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=datetime.timedelta(hours=8),
    MAX_CONTENT_LENGTH=2 * 1024 * 1024
)

FORCE_HTTPS = os.getenv('FORCE_HTTPS', '0').lower() in ('1', 'true', 'yes')
LOGIN_MAX_FAILURES = 10
LOGIN_LOCK_SECONDS = 15 * 60
LOGIN_FAILURES = {}

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    conn.execute('PRAGMA busy_timeout = 15000')
    return conn


TENANT_TABLES = ['quartos','hospedes','faixas_etarias','reservas','estoque','fluxo_caixa','ordens_servico']
PUBLIC_API_ENDPOINTS_WHEN_EXPIRED = {'api_planos','api_minha_assinatura','api_solicitar_assinatura'}
DEFAULT_PLANS = [
    ('Teste Grátis', 0.0, 10, 2, 7, 'Teste gratuito por 7 dias'),
    ('Básico', 79.90, 50, 5, 30, 'Até 50 quartos e 5 usuários'),
    ('Profissional', 149.90, 150, 10, 30, 'Até 150 quartos e 10 usuários'),
    ('Premium', 299.90, 500, 20, 30, 'Até 500 quartos e 20 usuários')
]

def csrf_token():
    token = session.get('_csrf_token')
    if not token:
        token = secrets.token_urlsafe(32)
        session['_csrf_token'] = token
    return token

def check_csrf():
    expected = session.get('_csrf_token')
    provided = request.form.get('csrf_token') or request.headers.get('X-CSRFToken')
    return bool(expected and provided and secrets.compare_digest(expected, provided))

def validate_password(password):
    if not isinstance(password, str) or len(password) < 10:
        return 'A senha deve ter pelo menos 10 caracteres.'
    if not any(ch.isupper() for ch in password):
        return 'A senha deve conter pelo menos uma letra maiúscula.'
    if not any(ch.islower() for ch in password):
        return 'A senha deve conter pelo menos uma letra minúscula.'
    if not any(ch.isdigit() for ch in password):
        return 'A senha deve conter pelo menos um número.'
    return None

def client_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr or 'unknown').split(',')[0].strip()

def login_is_locked(key):
    info = LOGIN_FAILURES.get(key)
    if not info:
        return False
    if time.time() >= info['until']:
        LOGIN_FAILURES.pop(key, None)
        return False
    return info['count'] >= LOGIN_MAX_FAILURES

def register_login_failure(key):
    now = time.time()
    info = LOGIN_FAILURES.get(key)
    if not info or now >= info['until']:
        LOGIN_FAILURES[key] = {'count': 1, 'until': now + LOGIN_LOCK_SECONDS}
    else:
        info['count'] += 1

def clear_login_failures(key):
    LOGIN_FAILURES.pop(key, None)

def add_column_if_missing(cursor, table, column_def):
    column_name = column_def.split()[0]
    cols = [r['name'] for r in cursor.execute(f'PRAGMA table_info({table})').fetchall()]
    if column_name not in cols:
        cursor.execute(f'ALTER TABLE {table} ADD COLUMN {column_def}')

def get_or_create_default_hotel(cursor):
    hotel = cursor.execute('SELECT id FROM hoteis ORDER BY id LIMIT 1').fetchone()
    if hotel:
        return hotel['id']
    cursor.execute(
        'INSERT INTO hoteis (nome, data_cadastro, local) VALUES (?, ?, ?)',
        ('Hotel Principal', datetime.date.today().isoformat(), 'Não informado')
    )
    return cursor.lastrowid

def ensure_planos(cursor):
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS planos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT UNIQUE NOT NULL,
            preco_mensal REAL NOT NULL DEFAULT 0,
            limite_quartos INTEGER NOT NULL DEFAULT 10,
            limite_usuarios INTEGER NOT NULL DEFAULT 2,
            dias_ciclo INTEGER NOT NULL DEFAULT 30,
            descricao TEXT,
            ativo INTEGER NOT NULL DEFAULT 1
        )
    ''')
    for nome, preco, lim_quartos, lim_usuarios, dias_ciclo, descricao in DEFAULT_PLANS:
        cursor.execute('''
            INSERT INTO planos (nome, preco_mensal, limite_quartos, limite_usuarios, dias_ciclo, descricao, ativo)
            SELECT ?, ?, ?, ?, ?, ?, 1
            WHERE NOT EXISTS (SELECT 1 FROM planos WHERE nome = ?)
        ''', (nome, preco, lim_quartos, lim_usuarios, dias_ciclo, descricao, nome))

def ensure_assinaturas(cursor):
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS assinaturas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hotel_id INTEGER NOT NULL,
            plano_id INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'TESTE',
            inicio TEXT NOT NULL,
            periodo_fim TEXT,
            trial_ate TEXT,
            gateway TEXT,
            cliente_externo TEXT,
            assinatura_externa TEXT,
            atualizado_em TEXT NOT NULL,
            FOREIGN KEY (hotel_id) REFERENCES hoteis(id),
            FOREIGN KEY (plano_id) REFERENCES planos(id)
        )
    ''')

def ensure_subscription_for_hotel(cursor, hotel_id):
    sub = cursor.execute('SELECT id FROM assinaturas WHERE hotel_id = ? ORDER BY id DESC LIMIT 1',(hotel_id,)).fetchone()
    if sub:
        return
    plano = cursor.execute("SELECT id FROM planos WHERE nome = 'Teste Grátis' LIMIT 1").fetchone()
    hoje = datetime.date.today()
    trial_ate = hoje + datetime.timedelta(days=7)
    cursor.execute('''
        INSERT INTO assinaturas
        (hotel_id, plano_id, status, inicio, periodo_fim, trial_ate, gateway, atualizado_em)
        VALUES (?, ?, 'TESTE', ?, ?, ?, 'interno', ?)
    ''', (hotel_id, plano['id'], hoje.isoformat(), trial_ate.isoformat(), trial_ate.isoformat(), datetime.datetime.utcnow().isoformat()))

def get_subscription(conn, hotel_id):
    row = conn.execute('''
        SELECT s.*, p.nome AS plano_nome, p.preco_mensal, p.limite_quartos, p.limite_usuarios, p.dias_ciclo
        FROM assinaturas s
        JOIN planos p ON p.id = s.plano_id
        WHERE s.hotel_id = ?
        ORDER BY s.id DESC
        LIMIT 1
    ''', (hotel_id,)).fetchone()
    if not row:
        return None
    data = dict(row)
    hoje = datetime.date.today()
    ativo = data['status'] == 'ATIVA'
    teste_ok = data['status'] == 'TESTE' and data.get('trial_ate') and hoje <= datetime.date.fromisoformat(data['trial_ate'][:10])
    if data.get('periodo_fim') and data['status'] == 'ATIVA':
        try:
            ativo = ativo and hoje <= datetime.date.fromisoformat(data['periodo_fim'][:10])
        except ValueError:
            ativo = False
    data['ativo'] = bool(ativo or teste_ok)
    data['teste'] = bool(teste_ok)
    return data

def subscription_blocked_response():
    return jsonify({
        'erro': 'Assinatura expirada ou inativa.',
        'codigo': 'ASSINATURA_INATIVA',
        'mensagem': 'Acesse a área de assinatura para renovar ou ativar um plano.'
    }), 402

def require_admin_role():
    return getattr(g, 'current_role', None) in ('admin','platform_admin')

def enforce_room_quota(conn, quantidade_nova=1):
    sub = getattr(g, 'subscription', None)
    if not sub:
        return True, None
    usados = conn.execute('SELECT COUNT(*) AS total FROM quartos WHERE hotel_id = ?',(g.hotel_id,)).fetchone()['total']
    if usados + quantidade_nova > int(sub['limite_quartos']):
        return False, f"Seu plano permite {sub['limite_quartos']} quarto(s). Limite atingido."
    return True, None

@app.before_request
def aplicar_protecoes():
    if FORCE_HTTPS and not request.is_secure and request.headers.get('X-Forwarded-Proto','').lower() != 'https':
        return redirect(request.url.replace('http://','https://',1), code=301)
    if request.method in ('POST','PUT','PATCH','DELETE'):
        if request.endpoint in ('login','registro') or request.path.startswith('/api/'):
            if not check_csrf():
                if request.path.startswith('/api/'):
                    return jsonify({'erro':'Token CSRF ausente ou inválido.'}), 403
                return 'Sessão expirada. Recarregue a página e tente novamente.', 403
    return None

@app.after_request
def headers_seguros(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    if request.path.startswith('/api/') or request.path in ('/login','/registro'):
        response.headers['Cache-Control'] = 'no-store'
    return response

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    # Tabela de Hoteis (Corrigido: adicionado 'local')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS hoteis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            data_cadastro TEXT NOT NULL,
            local TEXT
        )
    ''')

    # Tabela de Usuários vinculada ao hotel
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            hotel_id INTEGER,
            FOREIGN KEY (hotel_id) REFERENCES hoteis(id)
        )
    ''')
    
    try:
        cursor.execute("ALTER TABLE usuarios ADD COLUMN hotel_id INTEGER")
    except Exception:
        pass

    # Nova Tabela de Tipos de Quarto (Faltava no init_db original)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tipos_quarto (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            preco_diaria REAL NOT NULL,
            hotel_id INTEGER,
            ativo INTEGER DEFAULT 1,
            FOREIGN KEY (hotel_id) REFERENCES hoteis(id)
        )
    ''')

    # Tabela de Quartos (Corrigido: UNIQUE removido do 'numero' globalmente, adicionado 'andar' e 'hotel_id')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS quartos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            numero TEXT NOT NULL,
            tipo TEXT NOT NULL,
            preco_diaria REAL NOT NULL,
            status TEXT NOT NULL DEFAULT 'DISPONIVEL',
            andar INTEGER,
            hotel_id INTEGER,
            FOREIGN KEY (hotel_id) REFERENCES hoteis(id)
        )
    ''')

    # Tabela de Hóspedes
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS hospedes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            documento TEXT,
            telefone TEXT,
            email TEXT,
            observacoes TEXT,
            hotel_id INTEGER,
            FOREIGN KEY (hotel_id) REFERENCES hoteis(id)
        )
    ''')

    # Tabela de Faixas Etárias
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS faixas_etarias (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            idade_min INTEGER NOT NULL,
            idade_max INTEGER NOT NULL,
            valor_adicional REAL NOT NULL DEFAULT 0.0,
            hotel_id INTEGER,
            FOREIGN KEY (hotel_id) REFERENCES hoteis(id)
        )
    ''')
    
    try:
        cursor.execute("ALTER TABLE faixas_etarias ADD COLUMN valor_adicional REAL NOT NULL DEFAULT 0.0")
    except Exception:
        pass

    # Tabela de Reservas
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reservas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hospede_id INTEGER,
            quarto_numero TEXT,
            check_in TEXT NOT NULL,
            check_out TEXT NOT NULL,
            detalhes_pessoas TEXT,
            diarias INTEGER NOT NULL DEFAULT 1,
            status TEXT NOT NULL DEFAULT 'CONFIRMADA',
            valor_total REAL,
            status_pagamento TEXT NOT NULL DEFAULT 'PENDENTE',
            hotel_id INTEGER,
            FOREIGN KEY (hotel_id) REFERENCES hoteis(id)
        )
    ''')

    # Tabela de Estoque
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS estoque (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            item TEXT NOT NULL,
            categoria TEXT NOT NULL,
            quantidade INTEGER NOT NULL DEFAULT 0,
            preco_unitario REAL NOT NULL DEFAULT 0.0,
            hotel_id INTEGER,
            FOREIGN KEY (hotel_id) REFERENCES hoteis(id)
        )
    ''')

    # Tabela de Fluxo de Caixa
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS fluxo_caixa (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tipo TEXT NOT NULL,
            descricao TEXT NOT NULL,
            valor REAL NOT NULL,
            categoria TEXT NOT NULL,
            data TEXT NOT NULL,
            hotel_id INTEGER,
            FOREIGN KEY (hotel_id) REFERENCES hoteis(id)
        )
    ''')

    # Tabela de Ordens de Serviço
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ordens_servico (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            quarto TEXT NOT NULL,
            tipo TEXT NOT NULL,
            descricao TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'PENDENTE',
            hotel_id INTEGER,
            FOREIGN KEY (hotel_id) REFERENCES hoteis(id)
        )
    ''')

    # Insere usuário Admin Padrão
    cursor.execute('SELECT * FROM usuarios WHERE username = ?', ('admin',))
    if not cursor.fetchone():
        hashed_pw = generate_password_hash('admin123', method='pbkdf2:sha256')
        cursor.execute('INSERT INTO usuarios (username, password, role) VALUES (?, ?, ?)',
                       ('admin', hashed_pw, 'admin'))

    # Migração multi-hotel de dados já existentes.
    add_column_if_missing(cursor,'usuarios','hotel_id INTEGER')
    add_column_if_missing(cursor,'tipos_quarto','hotel_id INTEGER')
    add_column_if_missing(cursor,'quartos','hotel_id INTEGER')
    add_column_if_missing(cursor,'hospedes','hotel_id INTEGER')
    add_column_if_missing(cursor,'faixas_etarias','hotel_id INTEGER')
    add_column_if_missing(cursor,'reservas','hotel_id INTEGER')
    add_column_if_missing(cursor,'estoque','hotel_id INTEGER')
    add_column_if_missing(cursor,'fluxo_caixa','hotel_id INTEGER')
    add_column_if_missing(cursor,'ordens_servico','hotel_id INTEGER')

    ensure_planos(cursor)
    ensure_assinaturas(cursor)

    default_hotel_id = get_or_create_default_hotel(cursor)
    for table in TENANT_TABLES:
        cursor.execute(f'UPDATE {table} SET hotel_id = ? WHERE hotel_id IS NULL',(default_hotel_id,))
    cursor.execute('UPDATE usuarios SET hotel_id = ? WHERE hotel_id IS NULL',(default_hotel_id,))

    for hotel in cursor.execute('SELECT id FROM hoteis ORDER BY id').fetchall():
        hid=hotel['id']
        qtd=cursor.execute('SELECT COUNT(*) AS total FROM faixas_etarias WHERE hotel_id = ?',(hid,)).fetchone()['total']
        if qtd == 0:
            cursor.executemany(
                'INSERT INTO faixas_etarias (nome, idade_min, idade_max, valor_adicional, hotel_id) VALUES (?, ?, ?, ?, ?)',
                [('Criança (Até 11 anos)',0,11,0.0,hid),('Adulto Padrão',12,59,0.0,hid),('Idoso',60,120,0.0,hid)]
            )
        ensure_subscription_for_hotel(cursor,hid)

    for table in TENANT_TABLES:
        cursor.execute(f'CREATE INDEX IF NOT EXISTS idx_{table}_hotel_id ON {table}(hotel_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_usuarios_hotel_id ON usuarios(hotel_id)')

    conn.commit()
    conn.close()

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        conn=get_db()
        try:
            user=None
            if session.get('user_id'):
                user=conn.execute('SELECT id,username,role,hotel_id FROM usuarios WHERE id=? LIMIT 1',(session['user_id'],)).fetchone()
            if not user:
                auth=request.headers.get('Authorization','')
                token=auth[7:].strip() if auth.startswith('Bearer ') else None
                if not token:
                    return jsonify({'erro':'Token de acesso não fornecido.'}),401
                try:
                    data=jwt.decode(token,JWT_SECRET,algorithms=['HS256'])
                except jwt.ExpiredSignatureError:
                    return jsonify({'erro':'Token expirado.'}),401
                except jwt.InvalidTokenError:
                    return jsonify({'erro':'Token inválido.'}),401
                user=conn.execute('SELECT id,username,role,hotel_id FROM usuarios WHERE id=? OR username=? LIMIT 1',(data.get('user_id'),data.get('username'))).fetchone()
            if not user or not user['hotel_id']:
                return jsonify({'erro':'Usuário sem hotel vinculado.'}),403
            g.current_user_id=user['id']; g.current_user=user['username']; g.current_role=user['role']; g.hotel_id=user['hotel_id']
            g.subscription=get_subscription(conn,g.hotel_id)
            if request.endpoint not in PUBLIC_API_ENDPOINTS_WHEN_EXPIRED and (not g.subscription or not g.subscription['ativo']):
                return subscription_blocked_response()
            return f(user['username'],user['role'],*args,**kwargs)
        finally:
            conn.close()
    return decorated

@app.route('/')
def page_root():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username=request.form.get('username','').strip()
        password=request.form.get('password','')
        if not check_csrf():
            return render_template_string(LOGIN_TEMPLATE,erro='Sessão expirada. Recarregue a página.',csrf_token=csrf_token())
        lock_key=f'{client_ip()}::{username.lower()}'
        if login_is_locked(lock_key):
            return render_template_string(LOGIN_TEMPLATE,erro='Muitas tentativas. Tente novamente em alguns minutos.',csrf_token=csrf_token())
        conn=get_db()
        user=conn.execute('SELECT * FROM usuarios WHERE username=?',(username,)).fetchone()
        conn.close()
        if user and check_password_hash(user['password'],password):
            clear_login_failures(lock_key)
            session.clear(); session.permanent=True
            session['user_id']=user['id']; session['user']=user['username']; session['role']=user['role']; session['hotel_id']=user['hotel_id']
            csrf_token()
            return redirect(url_for('dashboard'))
        register_login_failure(lock_key)
        return render_template_string(LOGIN_TEMPLATE,erro='Usuário ou senha inválidos!',csrf_token=csrf_token())
    return render_template_string(LOGIN_TEMPLATE,csrf_token=csrf_token())

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        hotel_nome = request.form.get('hotel_nome', '').strip()

        if not username or not password or not hotel_nome:
            return render_template_string(REGISTER_TEMPLATE, erro='Preencha todos os campos obrigatórios!')

        conn = get_db()
        cursor = conn.cursor()

        existente = cursor.execute('SELECT * FROM usuarios WHERE username = ?', (username,)).fetchone()
        if existente:
            conn.close()
            return render_template_string(REGISTER_TEMPLATE, erro='Nome de usuário já está em uso!')

        try:
            data_cadastro = datetime.date.today().isoformat()

            cursor.execute('INSERT INTO hoteis (nome, data_cadastro, local) VALUES (?, ?, ?)',
                           (hotel_nome, data_cadastro, 'Goiânia'))
            hotel_id = cursor.lastrowid

            hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
            cursor.execute('INSERT INTO usuarios (username, password, role, hotel_id) VALUES (?, ?, ?, ?)',
                           (username, hashed_pw, 'admin', hotel_id))

            tipos_qtds = request.form.getlist('tipo_qtd[]')
            tipos_nomes = request.form.getlist('tipo_nome[]')
            tipos_precos = request.form.getlist('tipo_preco[]')

            contador_quarto = 1
            for i in range(len(tipos_nomes)):
                nome_t = tipos_nomes[i].strip()
                if not nome_t:
                    continue
                try:
                    qtd_t = int(tipos_qtds[i])
                    preco_t = float(tipos_precos[i].replace(',', '.'))
                except (ValueError, TypeError):
                    continue

                cursor.execute('''
                    INSERT INTO tipos_quarto (nome, preco_diaria, hotel_id, ativo)
                    VALUES (?, ?, ?, 1)
                ''', (nome_t, preco_t, hotel_id))

                for _ in range(qtd_t):
                    num_str = str(contador_quarto)
                    andar_val = contador_quarto // 100
                    cursor.execute('''
                        INSERT INTO quartos (numero, tipo, preco_diaria, andar, status, hotel_id)
                        VALUES (?, ?, ?, ?, 'DISPONIVEL', ?)
                    ''', (num_str, nome_t, preco_t, andar_val, hotel_id))
                    contador_quarto += 1

            conn.commit()
            conn.close()
            return render_template_string(LOGIN_TEMPLATE, sucesso="Hotel e Usuário cadastrados com sucesso! Faça seu login.")

        except Exception as e:
            conn.rollback()
            conn.close()
            return render_template_string(REGISTER_TEMPLATE, erro=f'Erro interno no cadastro: {str(e)}')

    return render_template_string(REGISTER_TEMPLATE)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template_string(DASHBOARD_TEMPLATE, csrf_token=csrf_token())

# ==========================================
# API - QUARTOS
# ==========================================
@app.route('/api/quartos', methods=['GET'])
@token_required
def listar_quartos(current_user, role):
    conn = get_db()
    quartos = [dict(row) for row in conn.cursor().execute('SELECT * FROM quartos ORDER BY CAST(numero AS INTEGER), numero').fetchall()]
    conn.close()
    return jsonify(quartos), 200

@app.route('/api/quartos', methods=['POST'])
@token_required
def criar_quarto(current_user, role):
    data = request.get_json() or {}
    numero = data.get('numero')
    tipo = data.get('tipo', 'Casal Deluxe')
    preco_diaria = float(data.get('preco_diaria', 200.0))

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            'INSERT INTO quartos (numero, tipo, preco_diaria, status) VALUES (?, ?, ?, ?)',
            (numero, tipo, preco_diaria, 'DISPONIVEL')
        )
        conn.commit()
    except Exception as e:
        conn.close()
        return jsonify({'erro': str(e)}), 400
    conn.close()
    return jsonify({'mensagem': 'Quarto cadastrado com sucesso!'}), 201

def gerar_numeros_quartos(quantidade, inicial, por_andar):
    if por_andar > 0:
        numeros = []
        andar, pos = divmod(inicial, 100)
        for _ in range(quantidade):
            numeros.append(str(andar * 100 + pos))
            pos += 1
            if pos > por_andar:
                andar += 1
                pos = 1
        return numeros
    return [str(inicial + i) for i in range(quantidade)]

@app.route('/api/quartos/lote', methods=['POST'])
@token_required
def criar_quartos_lote(current_user, role):
    data = request.get_json(silent=True) or {}
    try:
        quantidade = int(data.get('quantidade', 0))
        inicial = int(data.get('numero_inicial', 101))
        por_andar = int(data.get('por_andar', 0))
        preco = float(data.get('preco_diaria', 0))
    except (TypeError, ValueError):
        return jsonify({'erro': 'Valores numéricos inválidos.'}), 400

    tipo = str(data.get('tipo') or 'Standard').strip()[:60] or 'Standard'

    if quantidade < 1 or quantidade > 500:
        return jsonify({'erro': 'A quantidade deve ficar entre 1 e 500.'}), 400
    if inicial < 1:
        return jsonify({'erro': 'O primeiro número deve ser maior que zero.'}), 400
    if por_andar < 0 or por_andar > 99:
        return jsonify({'erro': 'Quartos por andar deve ficar entre 0 e 99.'}), 400
    if por_andar > 0 and (inicial % 100 < 1 or inicial % 100 > por_andar):
        return jsonify({'erro': f'Com {por_andar} quartos por andar, o primeiro número deve terminar entre 01 e {por_andar} (ex.: 101).'}), 400
    if preco <= 0:
        return jsonify({'erro': 'A diária base deve ser maior que zero.'}), 400

    numeros = gerar_numeros_quartos(quantidade, inicial, por_andar)

    conn = get_db()
    cursor = conn.cursor()
    criados = 0
    for numero in numeros:
        try:
            cursor.execute(
                'INSERT INTO quartos (numero, tipo, preco_diaria, status) VALUES (?, ?, ?, ?)',
                (numero, tipo, preco, 'DISPONIVEL')
            )
            criados += 1
        except Exception:
            pass # Ignora falhas se a lógica exigir restrições locais no futuro
    conn.commit()
    conn.close()

    ignorados = len(numeros) - criados
    if criados == 0:
        return jsonify({'erro': 'Todos esses números de quarto já existem. Nada foi criado.'}), 409

    mensagem = f'{criados} quarto(s) criado(s) ({numeros[0]} até {numeros[-1]}).'
    if ignorados:
        mensagem += f' {ignorados} já existiam e foram mantidos.'
    return jsonify({'mensagem': mensagem, 'criados': criados, 'ignorados': ignorados}), 201

@app.route('/api/quartos/<numero>', methods=['DELETE'])
@token_required
def deletar_quarto(current_user, role, numero):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM quartos WHERE numero = ?', (numero,))
    conn.commit()
    conn.close()
    return jsonify({'mensagem': 'Quarto excluído com sucesso!'}), 200

# ==========================================
# API - HÓSPEDES
# ==========================================
@app.route('/api/hospedes', methods=['GET'])
@token_required
def listar_hospedes(current_user, role):
    conn = get_db()
    hospedes = [dict(row) for row in conn.cursor().execute('SELECT * FROM hospedes ORDER BY nome').fetchall()]
    conn.close()
    return jsonify(hospedes), 200

@app.route('/api/hospedes', methods=['POST'])
@token_required
def criar_hospede(current_user, role):
    data = request.get_json() or {}
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO hospedes (nome, documento, telefone, email, observacoes) VALUES (?, ?, ?, ?, ?)',
        (data.get('nome'), data.get('documento'), data.get('telefone'), data.get('email'), data.get('observacoes'))
    )
    conn.commit()
    hid = cursor.lastrowid
    conn.close()
    return jsonify({'mensagem': 'Hóspede cadastrado com sucesso!', 'id': hid}), 201

# ==========================================
# API - FAIXAS ETÁRIAS (CATEGORIAS E TAXAS)
# ==========================================
@app.route('/api/faixas_etarias', methods=['GET'])
@token_required
def listar_faixas(current_user, role):
    conn = get_db()
    faixas = [dict(row) for row in conn.cursor().execute('SELECT * FROM faixas_etarias').fetchall()]
    conn.close()
    return jsonify(faixas), 200

@app.route('/api/faixas_etarias', methods=['POST'])
@token_required
def criar_faixa(current_user, role):
    data = request.get_json() or {}
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO faixas_etarias (nome, idade_min, idade_max, valor_adicional) VALUES (?, ?, ?, ?)',
        (data.get('nome'), int(data.get('idade_min', 0)), int(data.get('idade_max', 120)), float(data.get('valor_adicional', 0.0)))
    )
    conn.commit()
    conn.close()
    return jsonify({'mensagem': 'Faixa/Categoria criada!'}), 201

@app.route('/api/faixas_etarias/<int:fid>', methods=['DELETE'])
@token_required
def deletar_faixa(current_user, role, fid):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM faixas_etarias WHERE id = ?', (fid,))
    conn.commit()
    conn.close()
    return jsonify({'mensagem': 'Faixa removida!'}), 200

# ==========================================
# API - RESERVAS
# ==========================================
@app.route('/api/reservas', methods=['GET'])
@token_required
def listar_reservas(current_user, role):
    conn = get_db()
    query = '''
        SELECT r.*, h.nome as hospede_nome 
        FROM reservas r 
        LEFT JOIN hospedes h ON r.hospede_id = h.id 
        ORDER BY r.id DESC
    '''
    reservas = [dict(row) for row in conn.cursor().execute(query).fetchall()]
    conn.close()
    return jsonify(reservas), 200

@app.route('/api/reservas', methods=['POST'])
@token_required
def criar_reserva(current_user, role):
    data = request.get_json() or {}
    hospede_id = data.get('hospede_id')
    quarto_numero = data.get('quarto_numero')
    check_in = data.get('check_in')
    check_out = data.get('check_out')
    diarias = int(data.get('diarias', 1))
    composicao = data.get('composicao', [])

    conn = get_db()
    cursor = conn.cursor()
    
    q_data = cursor.execute('SELECT preco_diaria FROM quartos WHERE numero = ?', (quarto_numero,)).fetchone()
    if not q_data:
        conn.close()
        return jsonify({'erro': 'Quarto não encontrado.'}), 404
    
    preco_base_quarto = q_data['preco_diaria']
    valor_diaria_total = preco_base_quarto
    detalhes_str = []
    
    faixas = {f['id']: f for f in cursor.execute('SELECT * FROM faixas_etarias').fetchall()}

    for item in composicao:
        fid = int(item.get('faixa_id', 0))
        qtd = int(item.get('quantidade', 0))
        if qtd > 0 and fid in faixas:
            f = faixas[fid]
            try:
                adicional = float(f.get('valor_adicional', 0.0))
            except:
                adicional = 0.0
            
            subtotal_fx = adicional * qtd
            valor_diaria_total += subtotal_fx
            detalhes_str.append(f"{qtd}x {f['nome']}")

    if not detalhes_str:
        detalhes_str.append("Reserva Padrão")

    valor_total = valor_diaria_total * diarias
    detalhes_resumo = ", ".join(detalhes_str)

    cursor.execute(
        '''INSERT INTO reservas (hospede_id, quarto_numero, check_in, check_out, detalhes_pessoas, diarias, status, valor_total, status_pagamento) 
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
        (hospede_id, quarto_numero, check_in, check_out, detalhes_resumo, diarias, 'CONFIRMADA', valor_total, 'PENDENTE')
    )
    
    cursor.execute('INSERT INTO fluxo_caixa (tipo, descricao, valor, categoria, data) VALUES (?, ?, ?, ?, ?)',
                   ('ENTRADA', f"Reserva Quarto {quarto_numero} ({diarias} diárias)", valor_total, 'Hospedagem', datetime.date.today().isoformat()))

    cursor.execute('UPDATE quartos SET status = ? WHERE numero = ?', ('OCUPADO', quarto_numero))
    conn.commit()
    conn.close()
    return jsonify({'mensagem': 'Reserva efetuada com sucesso!', 'valor_total': valor_total}), 201

# ==========================================
# API - ESTOQUE & PDV
# ==========================================
@app.route('/api/estoque', methods=['GET', 'POST'])
@token_required
def gerenciar_estoque(current_user, role):
    conn = get_db()
    cursor = conn.cursor()
    if request.method == 'POST':
        data = request.get_json() or {}
        cursor.execute('INSERT INTO estoque (item, categoria, quantidade, preco_unitario) VALUES (?, ?, ?, ?)',
                       (data.get('item'), data.get('categoria'), int(data.get('quantidade', 0)), float(data.get('preco_unitario', 0.0))))
        conn.commit()
        conn.close()
        return jsonify({'mensagem': 'Item adicionado!'}), 201
    
    itens = [dict(row) for row in cursor.execute('SELECT * FROM estoque ORDER BY item').fetchall()]
    conn.close()
    return jsonify(itens), 200

@app.route('/api/estoque/<int:item_id>', methods=['DELETE'])
@token_required
def deletar_estoque(current_user, role, item_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM estoque WHERE id = ?', (item_id,))
    conn.commit()
    conn.close()
    return jsonify({'mensagem': 'Removido!'}), 200

# ==========================================
# API - FINANCEIRO
# ==========================================
@app.route('/api/financeiro', methods=['GET', 'POST'])
@token_required
def gerenciar_financeiro(current_user, role):
    conn = get_db()
    cursor = conn.cursor()
    if request.method == 'POST':
        data = request.get_json() or {}
        cursor.execute('INSERT INTO fluxo_caixa (tipo, descricao, valor, categoria, data) VALUES (?, ?, ?, ?, ?)',
                       (data.get('tipo'), data.get('descricao'), float(data.get('valor', 0)), data.get('categoria', 'Geral'), datetime.date.today().isoformat()))
        conn.commit()
        conn.close()
        return jsonify({'mensagem': 'Lançado!'}), 201

    lancamentos = [dict(row) for row in cursor.execute('SELECT * FROM fluxo_caixa ORDER BY id DESC').fetchall()]
    conn.close()
    return jsonify(lancamentos), 200

# ==========================================
# API - ORDENS DE SERVIÇO
# ==========================================
@app.route('/api/ordens', methods=['GET', 'POST'])
@token_required
def gerenciar_ordens(current_user, role):
    conn = get_db()
    cursor = conn.cursor()
    if request.method == 'POST':
        data = request.get_json() or {}
        cursor.execute('INSERT INTO ordens_servico (quarto, tipo, descricao, status) VALUES (?, ?, ?, ?)',
                       (data.get('quarto'), data.get('tipo'), data.get('descricao'), 'PENDENTE'))
        conn.commit()
        conn.close()
        return jsonify({'mensagem': 'OS criada!'}), 201

    ordens = [dict(row) for row in cursor.execute('SELECT * FROM ordens_servico ORDER BY id DESC').fetchall()]
    conn.close()
    return jsonify(ordens), 200

@app.route('/api/ordens/<int:oid>/status', methods=['PUT'])
@token_required
def atualizar_ordem(current_user, role, oid):
    data = request.get_json() or {}
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('UPDATE ordens_servico SET status = ? WHERE id = ?', (data.get('status', 'CONCLUIDA'), oid))
    conn.commit()
    conn.close()
    return jsonify({'mensagem': 'Status atualizado!'}), 200

# ==========================================
# API - RELATÓRIOS
# ==========================================
@app.route('/api/relatorios', methods=['GET'])
@token_required
def relatorios_gerenciais(current_user, role):
    conn = get_db()
    cursor = conn.cursor()
    total_quartos = cursor.execute('SELECT COUNT(*) as t FROM quartos').fetchone()['t'] or 1
    quartos_ocupados = cursor.execute("SELECT COUNT(*) as t FROM quartos WHERE status = 'OCUPADO'").fetchone()['t']
    res_receita = cursor.execute("SELECT SUM(valor_total) as s FROM reservas").fetchone()['s'] or 0.0
    total_reservas = cursor.execute("SELECT SUM(diarias) as s FROM reservas").fetchone()['s'] or 1

    taxa_ocupacao = round((quartos_ocupados / total_quartos) * 100, 2)
    adr = round(res_receita / total_reservas, 2) if total_reservas > 0 else 0.0
    revpar = round(adr * (taxa_ocupacao / 100), 2)

    conn.close()
    return jsonify({
        'total_quartos': total_quartos,
        'quartos_ocupados': quartos_ocupados,
        'taxa_ocupacao': taxa_ocupacao,
        'receita_total': round(res_receita, 2),
        'adr': adr,
        'revpar': revpar
    }), 200

# ==========================================
# API - SAAS / CONTA / PLANOS
# ==========================================
@app.route('/api/me')
@token_required
def api_me(current_user, role):
    conn=get_db()
    try:
        hotel=conn.execute('SELECT id,nome,data_cadastro,local FROM hoteis WHERE id=?',(g.hotel_id,)).fetchone()
        return jsonify({'usuario':{'id':g.current_user_id,'username':g.current_user,'role':g.current_role,'hotel_id':g.hotel_id},
                        'hotel':dict(hotel) if hotel else None,
                        'assinatura':get_subscription(conn,g.hotel_id)}),200
    finally:
        conn.close()

@app.route('/api/planos')
def api_planos():
    conn=get_db()
    try:
        return jsonify([dict(x) for x in conn.execute('SELECT id,nome,preco_mensal,limite_quartos,limite_usuarios,dias_ciclo,descricao FROM planos WHERE ativo=1 ORDER BY preco_mensal,id').fetchall()]),200
    finally:
        conn.close()

@app.route('/api/assinatura')
@token_required
def api_assinatura(current_user, role):
    conn=get_db()
    try:
        return jsonify(get_subscription(conn,g.hotel_id) or {'ativo':False,'status':'SEM_ASSINATURA'}),200
    finally:
        conn.close()

@app.route('/api/assinatura/limites')
@token_required
def api_assinatura_limites(current_user, role):
    conn=get_db()
    try:
        sub=get_subscription(conn,g.hotel_id)
        q=conn.execute('SELECT COUNT(*) total FROM quartos WHERE hotel_id=?',(g.hotel_id,)).fetchone()['total']
        u=conn.execute('SELECT COUNT(*) total FROM usuarios WHERE hotel_id=?',(g.hotel_id,)).fetchone()['total']
        return jsonify({'plano':sub,'quartos':{'usados':q,'limite':sub['limite_quartos'] if sub else 0},
                        'usuarios':{'usados':u,'limite':sub['limite_usuarios'] if sub else 0}}),200
    finally:
        conn.close()

@app.route('/api/assinatura/solicitar',methods=['POST'])
@token_required
def api_solicitar_plano(current_user, role):
    if not require_admin_role():
        return jsonify({'erro':'Apenas o administrador do hotel pode solicitar alteração de plano.'}),403
    data=request.get_json(silent=True) or {}
    try:
        plano_id=int(data.get('plano_id'))
    except (TypeError,ValueError):
        return jsonify({'erro':'Plano inválido.'}),400
    conn=get_db()
    try:
        plano=conn.execute('SELECT id,nome,preco_mensal,dias_ciclo FROM planos WHERE id=? AND ativo=1',(plano_id,)).fetchone()
        if not plano:
            return jsonify({'erro':'Plano não encontrado.'}),404
        checkout=os.getenv(f'SAAS_CHECKOUT_URL_{plano_id}',os.getenv('SAAS_CHECKOUT_URL','')).strip()
        return jsonify({'mensagem':'Solicitação registrada. O pagamento ainda precisa ser confirmado pelo gateway.',
                        'plano':dict(plano),'checkout_url':checkout or None}),202
    finally:
        conn.close()

@app.route('/api/admin/assinaturas/<int:hotel_id>',methods=['PUT'])
def api_admin_assinatura(hotel_id):
    esperado=os.getenv('SAAS_ADMIN_TOKEN','').strip()
    fornecido=request.headers.get('X-SaaS-Admin-Token','').strip()
    if not esperado or not fornecido or not secrets.compare_digest(esperado,fornecido):
        return jsonify({'erro':'Não autorizado.'}),401
    data=request.get_json(silent=True) or {}
    conn=get_db()
    try:
        plano_id=int(data.get('plano_id'))
        status=str(data.get('status','ATIVA')).upper()
        if status not in ('ATIVA','TESTE','SUSPENSA','CANCELADA'):
            return jsonify({'erro':'Status inválido.'}),400
        plano=conn.execute('SELECT id,dias_ciclo FROM planos WHERE id=? AND ativo=1',(plano_id,)).fetchone()
        if not plano:
            return jsonify({'erro':'Plano inválido.'}),400
        dias=int(data.get('dias',plano['dias_ciclo']))
        hoje=datetime.date.today()
        fim=hoje+datetime.timedelta(days=dias)
        conn.execute('INSERT INTO assinaturas (hotel_id,plano_id,status,inicio,periodo_fim,trial_ate,gateway,atualizado_em) VALUES (?,?,?,?,?,?,?,?)',
                     (hotel_id,plano_id,status,hoje.isoformat(),fim.isoformat(),fim.isoformat() if status=='TESTE' else None,'plataforma',datetime.datetime.utcnow().isoformat()))
        conn.commit()
        return jsonify({'mensagem':'Assinatura atualizada.','hotel_id':hotel_id}),200
    finally:
        conn.close()

# ==========================================
# TEMPLATES HTML
# ==========================================

REGISTER_TEMPLATE = """
<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <title>Cadastro - Hotel</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
<div class="container py-5" style="max-width: 600px;">
    <h2 class="mb-4 text-center">🏨 Cadastro de Novo Hotel</h2>
    
    {% if erro %}
    <div class="alert alert-danger">{{ erro }}</div>
    {% endif %}
    {% if sucesso %}
    <div class="alert alert-success">{{ sucesso }}</div>
    {% endif %}

    <form method="POST">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <div class="mb-3">
            <label class="form-label">Usuário (Admin)</label>
            <input type="text" name="username" class="form-control" required>
        </div>
        <div class="mb-3">
            <label class="form-label">Senha</label>
            <input type="password" name="password" class="form-control" required>
        </div>
        <div class="mb-3">
            <label class="form-label">Nome do Hotel</label>
            <input type="text" name="hotel_nome" class="form-control" required>
        </div>

        <div class="mb-3">
            <label class="form-label fw-bold">Configuração dos Quartos</label>
            <div id="container-tipos">
                <div class="row g-2 mb-2 linha-quarto align-items-end">
                    <div class="col-md-3">
                        <label class="form-label small">Qtd Quartos</label>
                        <input type="number" name="tipo_qtd[]" class="form-control" value="10" min="1" required>
                    </div>
                    <div class="col-md-4">
                        <label class="form-label small">Tipo de Quarto</label>
                        <input type="text" name="tipo_nome[]" class="form-control" value="Standard" placeholder="Ex: Standard, Luxo" required>
                    </div>
                    <div class="col-md-3">
                        <label class="form-label small">Diária (R$)</label>
                        <input type="number" step="0.01" name="tipo_preco[]" class="form-control" value="150.00" required>
                    </div>
                    <div class="col-md-2">
                        <button type="button" class="btn btn-outline-danger w-100" onclick="removerLinha(this)">Remover</button>
                    </div>
                </div>
            </div>
            
            <button type="button" class="btn btn-outline-primary btn-sm mt-2" onclick="adicionarLinha()">
                + Adicionar Outro Tipo de Quarto
            </button>
        </div>

        <button type="submit" class="btn btn-primary w-100 mt-3">Cadastrar Hotel</button>
    </form>
</div>

<script>
function adicionarLinha() {
    const container = document.getElementById('container-tipos');
    const novaLinha = document.createElement('div');
    novaLinha.className = 'row g-2 mb-2 linha-quarto align-items-end';
    novaLinha.innerHTML = `
        <div class="col-md-3">
            <input type="number" name="tipo_qtd[]" class="form-control" placeholder="Qtd" min="1" required>
        </div>
        <div class="col-md-4">
            <input type="text" name="tipo_nome[]" class="form-control" placeholder="Ex: Suíte, Luxo" required>
        </div>
        <div class="col-md-3">
            <input type="number" step="0.01" name="tipo_preco[]" class="form-control" placeholder="R$" required>
        </div>
        <div class="col-md-2">
            <button type="button" class="btn btn-outline-danger w-100" onclick="removerLinha(this)">Remover</button>
        </div>
    `;
    container.appendChild(novaLinha);
}

function removerLinha(botao) {
    const linhas = document.querySelectorAll('.linha-quarto');
    if (linhas.length > 1) {
        botao.closest('.linha-quarto').remove();
    } else {
        alert('Deve manter pelo menos um tipo de quarto configurado.');
    }
}
</script>
</body>
</html>
"""

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <title>Login - Hotel Master</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light d-flex align-items-center justify-content-center" style="height: 100vh;">
<div class="card p-4 shadow-sm" style="max-width: 400px; width: 100%;">
    <h3 class="text-center mb-3">🔑 Login - Hotel Master</h3>
    
    {% if erro %}
    <div class="alert alert-danger">{{ erro }}</div>
    {% endif %}
    {% if sucesso %}
    <div class="alert alert-success">{{ sucesso }}</div>
    {% endif %}

    <form method="POST">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <div class="mb-3">
            <label class="form-label">Usuário</label>
            <input type="text" name="username" class="form-control" required>
        </div>
        <div class="mb-3">
            <label class="form-label">Senha</label>
            <input type="password" name="password" class="form-control" required>
        </div>
        <button type="submit" class="btn btn-primary w-100">Entrar</button>
    </form>
    <div class="text-center mt-3">
        <a href="/registro" class="text-decoration-none">Cadastrar novo hotel</a>
    </div>
</div>
</body>
</html>
"""

DASHBOARD_TEMPLATE = '''<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="csrf-token" content="{{ csrf_token }}">
    <title>Hotel Master - Gestão Completa</title>
    <style>
        * { 
            box-sizing: border-box; 
            margin: 0; 
            padding: 0; 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
        }
        body { 
            display: flex; 
            background: #f4f6f9; 
            color: #333; 
            height: 100vh; 
            overflow: hidden; 
        }
        
        .sidebar { 
            width: 264px; 
            background: #111827; 
            color: #fff; 
            display: flex; 
            flex-direction: column; 
            padding: 20px 14px; 
            overflow-y: auto; 
            flex-shrink: 0; 
        }
        .brand { 
            display: flex; 
            align-items: center; 
            gap: 10px; 
            padding: 0 8px 18px; 
        }
        .brand-icon { 
            width: 38px; 
            height: 38px; 
            border-radius: 10px; 
            background: linear-gradient(135deg, #3498db, #2563eb); 
            display: flex; 
            align-items: center; 
            justify-content: center; 
            font-size: 20px; 
        }
        .brand-text { 
            font-size: 17px; 
            font-weight: 700; 
            line-height: 1.15; 
        }
        .brand-text small { 
            display: block; 
            font-size: 11px; 
            font-weight: 400; 
            color: #9ca3af; 
        }
        .user-card { 
            display: flex; 
            align-items: center; 
            gap: 10px; 
            background: #1f2937; 
            padding: 10px 12px; 
            border-radius: 10px; 
            margin-bottom: 18px; 
        }
        .user-card .avatar { 
            width: 34px; 
            height: 34px; 
            border-radius: 50%; 
            background: #3498db; 
            display: flex; 
            align-items: center; 
            justify-content: center; 
            font-weight: 700; 
        }
        .user-card strong { font-size: 13px; display: block; }
        .user-card span { font-size: 10px; color: #9ca3af; letter-spacing: .5px; }
        .menu-titulo { font-size: 10px; font-weight: 700; letter-spacing: 1px; text-transform: uppercase; color: #6b7280; padding: 0 12px 8px; }

        .sidebar nav { display: flex; flex-direction: column; gap: 2px; }
        .sidebar nav a { 
            display: flex; 
            align-items: center; 
            gap: 10px; 
            color: #9ca3af; 
            text-decoration: none; 
            padding: 10px 12px; 
            border-radius: 8px; 
            border-left: 3px solid transparent; 
            transition: background .15s, color .15s; 
            font-size: 14px; 
            cursor: pointer; 
            user-select: none; 
        }
        .sidebar nav a:hover { background: #1f2937; color: #fff; }
        .sidebar nav a.active { background: rgba(52,152,219,.16); color: #fff; border-left-color: #3498db; font-weight: 600; }
        .sidebar nav a.oculto { opacity: .45; font-style: italic; }
        .menu-icone { width: 22px; text-align: center; font-size: 16px; }
        .menu-nome { flex: 1; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

        .menu-controls { display: none; gap: 3px; }
        .sidebar.editando .menu-controls { display: flex; }
        .menu-btn { background: rgba(255,255,255,.1); border: none; color: #fff; width: 22px; height: 22px; border-radius: 5px; font-size: 11px; cursor: pointer; display: flex; align-items: center; justify-content: center; }
        .menu-btn:hover:not(:disabled) { background: rgba(255,255,255,.3); }
        .menu-btn:disabled { opacity: .25; cursor: default; }

        .sidebar-footer { margin-top: auto; padding-top: 16px; border-top: 1px solid #1f2937; display: flex; flex-direction: column; gap: 8px; }
        .btn-menu-editar, .btn-menu-restaurar, .btn-sair { width: 100%; padding: 10px; border-radius: 8px; font-size: 13px; font-weight: 600; cursor: pointer; text-align: center; text-decoration: none; border: 1px solid transparent; }
        .btn-menu-editar { background: #1f2937; color: #e5e7eb; border-color: #374151; }
        .btn-menu-editar:hover { background: #374151; }
        .sidebar.editando .btn-menu-editar { background: #3498db; color: #fff; border-color: #3498db; }
        .btn-menu-restaurar { background: transparent; color: #9ca3af; border-color: #374151; font-size: 12px; }
        .btn-menu-restaurar:hover { color: #fff; border-color: #6b7280; }
        .btn-sair { background: transparent; color: #f87171; }
        .btn-sair:hover { background: rgba(248,113,113,.12); }

        .main-content { flex: 1; display: flex; flex-direction: column; overflow-y: auto; }
        header { background: white; padding: 15px 30px; border-bottom: 1px solid #ddd; display: flex; justify-content: space-between; align-items: center; }
        .content-body { padding: 30px; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        
        .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.05); margin-bottom: 20px; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; background: white; }
        th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid #eee; font-size: 14px; }
        th { background: #f8f9fa; color: #333; }
        
        .badge { padding: 5px 10px; border-radius: 20px; font-size: 11px; font-weight: bold; }
        .badge.disponivel { background: #d4edda; color: #155724; }
        .badge.ocupado { background: #fff3cd; color: #856404; }
        .badge.pendente { background: #f8d7da; color: #721c24; }
        .badge.confirmada { background: #d4edda; color: #155724; }
        
        .btn { padding: 8px 14px; border: none; border-radius: 4px; cursor: pointer; font-weight: bold; font-size: 13px; }
        .btn-danger { background: #e74c3c; color: white; }
        .btn-primary { background: #3498db; color: white; }
        .btn-success { background: #2ecc71; color: white; }
        .btn-secondary { background: #7f8c8d; color: white; }
        
        .form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 15px; }
        .form-group { display: flex; flex-direction: column; }
        .form-group label { margin-bottom: 5px; font-weight: 600; font-size: 13px; }
        .form-group input, .form-group select { padding: 9px; border: 1px solid #ccc; border-radius: 4px; font-size: 14px; width: 100%; }
        
        .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 15px; margin-top: 15px; }
        .metric-card { background: #f8f9fa; padding: 15px; border-radius: 6px; border-left: 4px solid #3498db; }
        .metric-card h5 { color: #666; font-size: 12px; margin-bottom: 5px; }
        .metric-card p { font-size: 20px; font-weight: bold; color: #333; }
    </style>
</head>
<body>
    <div class="sidebar" id="sidebar">
        <div class="brand">
            <div class="brand-icon">🏨</div>
            <div class="brand-text">Hotel Master<small>Gestão hoteleira</small></div>
        </div>
        <div class="user-card">
            <div class="avatar">A</div>
            <div><strong>Administrador</strong><span>USER</span></div>
        </div>

        <div class="menu-titulo">Menu</div>
        <nav id="menu-lateral">
            <!-- Gerado dinamicamente -->
        </nav>

        <div class="sidebar-footer">
            <button type="button" id="btn-editar-menu" class="btn-menu-editar" onclick="alternarEdicaoMenu()">✏️ Editar menu</button>
            <button type="button" id="btn-restaurar-menu" class="btn-menu-restaurar" style="display:none;" onclick="restaurarMenuPadrao()">↺ Restaurar padrão</button>
            <a href="/logout" class="btn-sair">⎋ Sair</a>
        </div>
    </div>

    <div class="main-content">
        <header>
            <h3 id="page-title">Gerenciamento de Quartos</h3>
        </header>
        <div class="content-body">
            
            <div id="tab-quartos" class="tab-content active">
                <div class="card">
                    <h4>Cadastrar Novo Quarto</h4>
                    <form id="form-quarto" onsubmit="criarQuarto(event)" class="form-grid">
                        <div class="form-group">
                            <label>Número</label>
                            <input type="text" id="q-numero" placeholder="ex: 103" required>
                        </div>
                        <div class="form-group">
                            <label>Tipo (Editável livremente)</label>
                            <input type="text" id="q-tipo" placeholder="ex: Casal Deluxe" required>
                        </div>
                        <div class="form-group">
                            <label>Preço Diária Estabelecida (R$)</label>
                            <input type="number" step="0.01" id="q-preco" required>
                        </div>
                        <div class="form-group" style="justify-content: flex-end;">
                            <button type="submit" class="btn btn-primary" style="margin-top: 22px;">Cadastrar</button>
                        </div>
                    </form>
                </div>
                
                <div class="card">
                    <h4>⚡ Gerar Quartos Padrão em Lote</h4>
                    <p style="font-size: 13px; color: #666; margin-top: 6px;">Informe a quantidade e o modelo padrão: o sistema cria todos os quartos de uma vez, já numerados.</p>
                    <form id="form-quartos-lote" onsubmit="gerarQuartosLote(event)" class="form-grid">
                        <div class="form-group">
                            <label>Quantidade de quartos</label>
                            <input type="number" id="lote-qtd" min="1" max="500" value="10" required oninput="atualizarPrevisaoLote()">
                        </div>
                        <div class="form-group">
                            <label>Tipo padrão</label>
                            <input type="text" id="lote-tipo" value="Standard" maxlength="60" required>
                        </div>
                        <div class="form-group">
                            <label>Diária estabelecida base (R$)</label>
                            <input type="number" step="0.01" min="0.01" id="lote-preco" required>
                        </div>
                        <div class="form-group">
                            <label>Primeiro número</label>
                            <input type="number" id="lote-inicial" min="1" value="101" required oninput="atualizarPrevisaoLote()">
                        </div>
                        <div class="form-group">
                            <label>Quartos por andar (0 = sequencial)</label>
                            <input type="number" id="lote-por-andar" min="0" max="99" value="10" oninput="atualizarPrevisaoLote()">
                        </div>
                        <div class="form-group" style="justify-content: flex-end;">
                            <button type="submit" class="btn btn-success" style="margin-top: 22px;">Gerar quartos</button>
                        </div>
                    </form>
                    <p id="lote-previa" style="margin-top: 12px; font-size: 13px; color: #2c3e50;"></p>
                </div>
                
                <div class="card">
                    <h4>Quartos Cadastrados <span id="contagem-quartos" style="font-weight: normal; color: #888;"></span></h4>
                    <table>
                        <thead>
                            <tr>
                                <th>Número</th>
                                <th>Tipo</th>
                                <th>Diária Estabelecida</th>
                                <th>Status</th>
                                <th>Ações</th>
                            </tr>
                        </thead>
                        <tbody id="tabela-quartos"></tbody>
                    </table>
                </div>
            </div>

            <div id="tab-hospedes" class="tab-content">
                <div class="card">
                    <h4>Novo Hóspede</h4>
                    <form id="form-hospede" onsubmit="criarHospede(event)" class="form-grid">
                        <div class="form-group"><label>Nome</label><input type="text" id="h-nome" required></div>
                        <div class="form-group"><label>Documento</label><input type="text" id="h-doc"></div>
                        <div class="form-group"><label>Telefone</label><input type="text" id="h-tel"></div>
                        <div class="form-group"><label>E-mail</label><input type="email" id="h-email"></div>
                        <div class="form-group" style="grid-column: span 2;">
                            <button type="submit" class="btn btn-primary">Salvar Hóspede</button>
                        </div>
                    </form>
                </div>
                <div class="card">
                    <h4>Hóspedes Cadastrados</h4>
                    <table>
                        <thead>
                            <tr>
                                <th>Nome</th>
                                <th>Documento</th>
                                <th>Telefone</th>
                                <th>E-mail</th>
                            </tr>
                        </thead>
                        <tbody id="tabela-hospedes"></tbody>
                    </table>
                </div>
            </div>

            <div id="tab-faixas" class="tab-content">
                <div class="card">
                    <h4>Cadastrar Categoria / Faixa Etária</h4>
                    <p style="font-size: 13px; color: #666; margin-bottom: 15px;">Cadastre categorias de pessoas. A diária base já é a do quarto. Você pode configurar um valor adicional fixo caso a pessoa gere um custo extra (ex: Cama extra R$50,00).</p>
                    <form id="form-faixa" onsubmit="criarFaixa(event)" class="form-grid">
                        <div class="form-group"><label>Nome (ex: Criança, Adulto, Cama Extra)</label><input type="text" id="fe-nome" required></div>
                        <div class="form-group"><label>Idade Mínima</label><input type="number" id="fe-min" required></div>
                        <div class="form-group"><label>Idade Máxima</label><input type="number" id="fe-max" required></div>
                        <div class="form-group"><label>Valor Adicional na Diária (R$)</label><input type="number" step="0.01" id="fe-adicional" value="0.0" required></div>
                        <div class="form-group" style="justify-content: flex-end;">
                            <button type="submit" class="btn btn-primary" style="margin-top: 22px;">Salvar Categoria</button>
                        </div>
                    </form>
                </div>
                <div class="card">
                    <h4>Categorias Cadastradas</h4>
                    <table>
                        <thead>
                            <tr>
                                <th>Nome</th>
                                <th>Idade</th>
                                <th>Taxa Adicional (R$)</th>
                                <th>Ações</th>
                            </tr>
                        </thead>
                        <tbody id="tabela-faixas"></tbody>
                    </table>
                </div>
            </div>

            <div id="tab-reservas" class="tab-content">
                <div class="card">
                    <h4>Efetuar Reserva</h4>
                    <form id="form-reserva" onsubmit="criarReserva(event)" class="form-grid">
                        <div class="form-group"><label>ID Hóspede Principal</label><input type="number" id="r-hospede-id" required></div>
                        <div class="form-group"><label>Número do Quarto</label><input type="text" id="r-quarto-num" required></div>
                        <div class="form-group"><label>Check-in</label><input type="date" id="r-checkin" required></div>
                        <div class="form-group"><label>Check-out</label><input type="date" id="r-checkout" required></div>
                        <div class="form-group"><label>Quantidade de Diárias</label><input type="number" id="r-diarias" value="1" required></div>
                        <div class="form-group" style="grid-column: span 2;">
                            <label>Composição Adicional da Reserva</label>
                            <div id="container-faixas-reserva" style="display: flex; gap: 15px; margin-top: 8px; flex-wrap: wrap;"></div>
                        </div>
                        <div class="form-group" style="grid-column: span 2;">
                            <button type="submit" class="btn btn-primary">Calcular e Salvar Reserva</button>
                        </div>
                    </form>
                </div>
                <div class="card">
                    <h4>Lista de Reservas</h4>
                    <table>
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Hóspede ID</th>
                                <th>Quarto</th>
                                <th>Check-in / Out</th>
                                <th>Composição</th>
                                <th>Diárias</th>
                                <th>Total (R$)</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody id="tabela-reservas"></tbody>
                    </table>
                </div>
            </div>

            <div id="tab-estoque" class="tab-content">
                <div class="card">
                    <h4>Adicionar Produto ao Estoque / PDV</h4>
                    <form id="form-estoque" onsubmit="criarEstoque(event)" class="form-grid">
                        <div class="form-group"><label>Nome do Item</label><input type="text" id="e-item" required></div>
                        <div class="form-group"><label>Categoria</label><input type="text" id="e-cat" required></div>
                        <div class="form-group"><label>Quantidade</label><input type="number" id="e-qtd" required></div>
                        <div class="form-group"><label>Preço Unitário (R$)</label><input type="number" step="0.01" id="e-preco" required></div>
                        <div class="form-group" style="justify-content: flex-end;">
                            <button type="submit" class="btn btn-primary" style="margin-top: 22px;">Adicionar</button>
                        </div>
                    </form>
                </div>
                <div class="card">
                    <h4>Itens em Estoque</h4>
                    <table>
                        <thead>
                            <tr>
                                <th>Item</th>
                                <th>Categoria</th>
                                <th>Quantidade</th>
                                <th>Preço Unitário</th>
                                <th>Ações</th>
                            </tr>
                        </thead>
                        <tbody id="tabela-estoque"></tbody>
                    </table>
                </div>
            </div>

            <div id="tab-financeiro" class="tab-content">
                <div class="card">
                    <h4>Novo Lançamento Financeiro (Caixa)</h4>
                    <form id="form-financeiro" onsubmit="criarFinanceiro(event)" class="form-grid">
                        <div class="form-group">
                            <label>Tipo</label>
                            <select id="f-tipo">
                                <option value="ENTRADA">ENTRADA</option>
                                <option value="SAIDA">SAÍDA</option>
                            </select>
                        </div>
                        <div class="form-group"><label>Descrição</label><input type="text" id="f-desc" required></div>
                        <div class="form-group"><label>Valor (R$)</label><input type="number" step="0.01" id="f-valor" required></div>
                        <div class="form-group"><label>Categoria</label><input type="text" id="f-cat" value="Geral" required></div>
                        <div class="form-group" style="justify-content: flex-end;">
                            <button type="submit" class="btn btn-primary" style="margin-top: 22px;">Lançar</button>
                        </div>
                    </form>
                </div>
                <div class="card">
                    <h4>Fluxo de Caixa</h4>
                    <table>
                        <thead>
                            <tr>
                                <th>Data</th>
                                <th>Tipo</th>
                                <th>Descrição</th>
                                <th>Categoria</th>
                                <th>Valor</th>
                            </tr>
                        </thead>
                        <tbody id="tabela-financeiro"></tbody>
                    </table>
                </div>
            </div>

            <div id="tab-ordens" class="tab-content">
                <div class="card">
                    <h4>Nova Ordem de Serviço</h4>
                    <form id="form-ordem" onsubmit="criarOrdem(event)" class="form-grid">
                        <div class="form-group"><label>Quarto</label><input type="text" id="os-quarto" placeholder="ex: 101" required></div>
                        <div class="form-group">
                            <label>Tipo</label>
                            <select id="os-tipo">
                                <option value="Limpeza">Limpeza</option>
                                <option value="Manutenção Elétrica">Manutenção Elétrica</option>
                                <option value="Manutenção Hidráulica">Manutenção Hidráulica</option>
                                <option value="Outros">Outros</option>
                            </select>
                        </div>
                        <div class="form-group"><label>Descrição</label><input type="text" id="os-desc" required></div>
                        <div class="form-group" style="justify-content: flex-end;">
                            <button type="submit" class="btn btn-primary" style="margin-top: 22px;">Criar OS</button>
                        </div>
                    </form>
                </div>
                <div class="card">
                    <h4>Ordens de Serviço</h4>
                    <table>
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Quarto</th>
                                <th>Tipo</th>
                                <th>Descrição</th>
                                <th>Status</th>
                                <th>Ação</th>
                            </tr>
                        </thead>
                        <tbody id="tabela-ordens"></tbody>
                    </table>
                </div>
            </div>

            <div id="tab-relatorios" class="tab-content">
                <div class="card">
                    <h4>Relatórios Gerenciais Avançados</h4>
                    <div class="metrics-grid" id="dados-relatorio">Carregando métricas...</div>
                </div>
            </div>

            <div id="tab-whatsapp" class="tab-content">
                <div class="card">
                    <h4>Central de Mensagens WhatsApp</h4>
                    <div class="form-grid">
                        <div class="form-group"><label>Telefone do Hóspede (com DDD)</label><input type="text" id="wa-tel" placeholder="5561999999999"></div>
                        <div class="form-group" style="grid-column: span 2;">
                            <label>Modelo de Mensagem</label>
                            <select id="wa-template" onchange="preencherTemplateWhatsApp()">
                                <option value="Olá! Sua reserva no Hotel Master está confirmada. Aguardamos sua visita!">Confirmação de Reserva</option>
                                <option value="Olá! Lembramos que seu check-out é amanhã. Tenha uma excelente estadia!">Lembrete de Check-out</option>
                                <option value="Olá! Agradecemos sua estadia no Hotel Master. Esperamos vê-lo em breve!">Agradecimento Pós-Estadia</option>
                            </select>
                        </div>
                        <div class="form-group" style="grid-column: span 2;"><label>Mensagem Personalizada</label><input type="text" id="wa-msg"></div>
                        <div class="form-group">
                            <button type="button" class="btn btn-success" onclick="enviarWhatsApp()">Enviar via WhatsApp</button>
                        </div>
                    </div>
                </div>
            </div>

        </div>
    </div>

    <script>
        let faixasGlobais = [];

        const MENU_KEY = 'hotel_master_menu_v2';
        let abaAtual = 'quartos';
        let menuEditando = false;

        const menuItensPadrao = [
            { id: 'quartos',    icone: '🛏️', nome: 'Quartos',               visivel: true },
            { id: 'hospedes',   icone: '👥', nome: 'Hóspedes',              visivel: true },
            { id: 'faixas',     icone: '⚙️', nome: 'Categorias Pessoas',    visivel: true },
            { id: 'reservas',   icone: '📅', nome: 'Reservas & Preços',     visivel: true },
            { id: 'estoque',    icone: '🛒', nome: 'PDV & Estoque',         visivel: true },
            { id: 'financeiro', icone: '💰', nome: 'Financeiro',            visivel: true },
            { id: 'ordens',     icone: '🛠️', nome: 'Ordens de Serviço',     visivel: true },
            { id: 'relatorios', icone: '📊', nome: 'Relatórios (ADR/RevPAR)', visivel: true },
            { id: 'whatsapp',   icone: '💬', nome: 'WhatsApp',              visivel: true }
        ];

        function lerJsonLocal(chave) {
            try { return JSON.parse(localStorage.getItem(chave)); } catch (e) { return null; }
        }

        function obterMenuConfig() {
            let salvo = lerJsonLocal(MENU_KEY);
            if (!Array.isArray(salvo)) salvo = lerJsonLocal('hotel_master_menu'); 
            const padrao = JSON.parse(JSON.stringify(menuItensPadrao));
            if (!Array.isArray(salvo)) return padrao;

            const resultado = [];
            salvo.forEach(s => {
                const p = padrao.find(x => x.id === s.id);
                if (!p) return;
                const nomePersonalizado = (s.icone && typeof s.nome === 'string' && s.nome.trim()) ? s.nome.trim() : p.nome;
                resultado.push({ ...p, nome: nomePersonalizado, visivel: s.visivel !== false });
            });
            padrao.forEach(p => { if (!resultado.some(r => r.id === p.id)) resultado.push(p); });
            return resultado;
        }

        function salvarMenuConfig(menu) {
            localStorage.setItem(MENU_KEY, JSON.stringify(menu));
            renderizarMenu();
        }

        function criarBotaoMenu(texto, titulo, desabilitado, acao) {
            const b = document.createElement('button');
            b.type = 'button';
            b.className = 'menu-btn';
            b.textContent = texto;
            b.title = titulo;
            b.disabled = desabilitado;
            b.addEventListener('click', (ev) => { ev.stopPropagation(); acao(); });
            return b;
        }

        function renderizarMenu() {
            const menu = obterMenuConfig();
            const nav = document.getElementById('menu-lateral');
            nav.innerHTML = '';

            menu.forEach((item, index) => {
                if (!item.visivel && !menuEditando) return;

                const a = document.createElement('a');
                a.dataset.id = item.id;
                if (item.id === abaAtual && item.visivel) a.classList.add('active');
                if (!item.visivel) a.classList.add('oculto');

                const icone = document.createElement('span');
                icone.className = 'menu-icone';
                icone.textContent = item.icone;

                const nome = document.createElement('span');
                nome.className = 'menu-nome';
                nome.textContent = item.nome;

                const controles = document.createElement('div');
                controles.className = 'menu-controls';
                controles.appendChild(criarBotaoMenu('▲', 'Subir', index === 0, () => moverMenu(index, -1)));
                controles.appendChild(criarBotaoMenu('▼', 'Descer', index === menu.length - 1, () => moverMenu(index, 1)));
                controles.appendChild(criarBotaoMenu('✎', 'Renomear', false, () => renomearMenu(index)));
                controles.appendChild(item.visivel
                    ? criarBotaoMenu('✕', 'Ocultar', false, () => alternarVisibilidadeMenu(index))
                    : criarBotaoMenu('＋', 'Mostrar', false, () => alternarVisibilidadeMenu(index)));

                a.append(icone, nome, controles);
                a.addEventListener('click', () => { if (item.visivel) switchTab(item.id); });
                nav.appendChild(a);
            });
        }

        function moverMenu(index, direcao) {
            const menu = obterMenuConfig();
            const novoIndex = index + direcao;
            if (novoIndex < 0 || novoIndex >= menu.length) return;
            [menu[index], menu[novoIndex]] = [menu[novoIndex], menu[index]];
            salvarMenuConfig(menu);
        }

        function alternarVisibilidadeMenu(index) {
            const menu = obterMenuConfig();
            menu[index].visivel = !menu[index].visivel;
            salvarMenuConfig(menu);
        }

        function renomearMenu(index) {
            const menu = obterMenuConfig();
            const novo = prompt('Novo nome para este item do menu:', menu[index].nome);
            if (novo === null) return;
            const limpo = novo.trim();
            if (!limpo) return;
            menu[index].nome = limpo.slice(0, 40);
            salvarMenuConfig(menu);
            atualizarTituloPagina();
        }

        function alternarEdicaoMenu() {
            menuEditando = !menuEditando;
            document.getElementById('sidebar').classList.toggle('editando', menuEditando);
            document.getElementById('btn-editar-menu').textContent = menuEditando ? '✔ Concluir edição' : '✏️ Editar menu';
            document.getElementById('btn-restaurar-menu').style.display = menuEditando ? 'block' : 'none';
            renderizarMenu();
        }

        function restaurarMenuPadrao() {
            if (!confirm('Restaurar o menu para a ordem e os nomes originais?')) return;
            localStorage.removeItem(MENU_KEY);
            localStorage.removeItem('hotel_master_menu');
            switchTab('quartos');
        }

        function atualizarTituloPagina() {
            const item = obterMenuConfig().find(i => i.id === abaAtual);
            document.getElementById('page-title').innerText = item ? item.nome : 'Painel';
        }

        function switchTab(tabName) {
            abaAtual = tabName;
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
            const aba = document.getElementById('tab-' + tabName);
            if (aba) aba.classList.add('active');
            atualizarTituloPagina();
            renderizarMenu(); 

            if(tabName === 'quartos') carregarQuartos();
            if(tabName === 'hospedes') carregarHospedes();
            if(tabName === 'faixas') carregarFaixas();
            if(tabName === 'reservas') { carregarFaixasParaReserva(); carregarReservas(); }
            if(tabName === 'estoque') carregarEstoque();
            if(tabName === 'financeiro') carregarFinanceiro();
            if(tabName === 'ordens') carregarOrdens();
            if(tabName === 'relatorios') carregarRelatorios();
            if(tabName === 'whatsapp') preencherTemplateWhatsApp();
        }

        function escaparHtml(valor) {
            const d = document.createElement('div');
            d.textContent = valor == null ? '' : String(valor);
            return d.innerHTML;
        }

        async function carregarQuartos() {
            const res = await fetch('/api/quartos');
            const data = await res.json();
            const tbody = document.getElementById('tabela-quartos');
            tbody.innerHTML = '';
            
            data.forEach(q => {
                let tr = document.createElement('tr');
                tr.innerHTML = `
                    <td><b>${escaparHtml(q.numero)}</b></td>
                    <td>${escaparHtml(q.tipo)}</td>
                    <td>R$ ${q.preco_diaria.toFixed(2)}</td>
                    <td><span class="badge ${q.status.toLowerCase()}">${escaparHtml(q.status)}</span></td>
                    <td><button class="btn btn-danger" onclick="deletarQuarto('${escaparHtml(q.numero)}')">Excluir</button></td>
                `;
                tbody.appendChild(tr);
            });
            
            const contagem = document.getElementById('contagem-quartos');
            if (contagem) contagem.textContent = '(' + data.length + ')';
            atualizarPrevisaoLote();
        }

        function calcularNumerosLote(qtd, inicial, porAndar) {
            const numeros = [];
            if (porAndar > 0) {
                let andar = Math.floor(inicial / 100);
                let pos = inicial % 100;
                for (let i = 0; i < qtd; i++) {
                    numeros.push(andar * 100 + pos);
                    pos++;
                    if (pos > porAndar) { andar++; pos = 1; }
                }
            } else {
                for (let i = 0; i < qtd; i++) numeros.push(inicial + i);
            }
            return numeros;
        }

        function lerParametrosLote() {
            return {
                qtd: parseInt(document.getElementById('lote-qtd').value, 10),
                inicial: parseInt(document.getElementById('lote-inicial').value, 10),
                porAndar: parseInt(document.getElementById('lote-por-andar').value || '0', 10)
            };
        }

        function validarParametrosLote(p) {
            if (!Number.isInteger(p.qtd) || p.qtd < 1 || p.qtd > 500) return 'Informe uma quantidade entre 1 e 500.';
            if (!Number.isInteger(p.inicial) || p.inicial < 1) return 'Informe um primeiro número válido.';
            if (!Number.isInteger(p.porAndar) || p.porAndar < 0 || p.porAndar > 99) return 'Quartos por andar deve ficar entre 0 e 99.';
            if (p.porAndar > 0 && (p.inicial % 100 < 1 || p.inicial % 100 > p.porAndar)) {
                return 'Com ' + p.porAndar + ' quartos por andar, o primeiro número deve terminar entre 01 e ' + p.porAndar + ' (ex.: 101).';
            }
            return '';
        }

        function atualizarPrevisaoLote() {
            const el = document.getElementById('lote-previa');
            if (!el) return;
            const p = lerParametrosLote();
            const erro = validarParametrosLote(p);
            if (erro) { el.style.color = '#c0392b'; el.textContent = erro; return; }
            const nums = calcularNumerosLote(p.qtd, p.inicial, p.porAndar);
            el.style.color = '#2c3e50';
            el.textContent = 'Serão criados ' + nums.length + ' quarto(s): ' + nums[0] + ' até ' + nums[nums.length - 1] + '.';
        }

        async function gerarQuartosLote(e) {
            e.preventDefault();
            const p = lerParametrosLote();
            const erro = validarParametrosLote(p);
            if (erro) { alert(erro); return; }
            const preco = parseFloat(document.getElementById('lote-preco').value);
            if (!(preco > 0)) { alert('Informe a diária base.'); return; }

            const nums = calcularNumerosLote(p.qtd, p.inicial, p.porAndar);
            if (!confirm('Criar ' + nums.length + ' quartos (' + nums[0] + ' até ' + nums[nums.length - 1] + ')?')) return;

            const res = await fetch('/api/quartos/lote', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    quantidade: p.qtd,
                    numero_inicial: p.inicial,
                    por_andar: p.porAndar,
                    tipo: document.getElementById('lote-tipo').value,
                    preco_diaria: preco
                })
            });
            const data = await res.json().catch(() => ({}));
            if (res.ok) {
                alert(data.mensagem);
                carregarQuartos();
            } else {
                alert(data.erro || 'Não foi possível gerar os quartos.');
            }
        }

        async function criarQuarto(e) {
            e.preventDefault();
            await fetch('/api/quartos', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    numero: document.getElementById('q-numero').value,
                    tipo: document.getElementById('q-tipo').value,
                    preco_diaria: parseFloat(document.getElementById('q-preco').value),
                    status: 'DISPONIVEL'
                })
            });
            document.getElementById('form-quarto').reset();
            carregarQuartos();
        }

        async function deletarQuarto(numero) {
            if(!confirm('Deseja excluir este quarto?')) return;
            await fetch(`/api/quartos/${numero}`, { method: 'DELETE' });
            carregarQuartos();
        }

        async function carregarHospedes() {
            const res = await fetch('/api/hospedes');
            const data = await res.json();
            const tbody = document.getElementById('tabela-hospedes');
            tbody.innerHTML = '';
            data.forEach(h => {
                let tr = document.createElement('tr');
                tr.innerHTML = `
                    <td>${escaparHtml(h.nome)}</td>
                    <td>${escaparHtml(h.documento || '-')}</td>
                    <td>${escaparHtml(h.telefone || '-')}</td>
                    <td>${escaparHtml(h.email || '-')}</td>
                `;
                tbody.appendChild(tr);
            });
        }

        async function criarHospede(e) {
            e.preventDefault();
            await fetch('/api/hospedes', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    nome: document.getElementById('h-nome').value,
                    documento: document.getElementById('h-doc').value,
                    telefone: document.getElementById('h-tel').value,
                    email: document.getElementById('h-email').value,
                    observacoes: ''
                })
            });
            document.getElementById('form-hospede').reset();
            carregarHospedes();
        }

        async function carregarFaixas() {
            const res = await fetch('/api/faixas_etarias');
            faixasGlobais = await res.json();
            const tbody = document.getElementById('tabela-faixas');
            tbody.innerHTML = '';
            faixasGlobais.forEach(f => {
                let tr = document.createElement('tr');
                tr.innerHTML = `
                    <td><b>${escaparHtml(f.nome)}</b></td>
                    <td>${f.idade_min} a ${f.idade_max} anos</td>
                    <td>R$ ${f.valor_adicional.toFixed(2)}</td>
                    <td><button class="btn btn-danger" onclick="deletarFaixa(${f.id})">Excluir</button></td>
                `;
                tbody.appendChild(tr);
            });
        }

        async function criarFaixa(e) {
            e.preventDefault();
            await fetch('/api/faixas_etarias', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    nome: document.getElementById('fe-nome').value,
                    idade_min: parseInt(document.getElementById('fe-min').value),
                    idade_max: parseInt(document.getElementById('fe-max').value),
                    valor_adicional: parseFloat(document.getElementById('fe-adicional').value)
                })
            });
            document.getElementById('form-faixa').reset();
            carregarFaixas();
        }

        async function deletarFaixa(id) {
            if(!confirm('Deseja excluir esta categoria?')) return;
            await fetch(`/api/faixas_etarias/${id}`, { method: 'DELETE' });
            carregarFaixas();
        }

        async function carregarFaixasParaReserva() {
            const res = await fetch('/api/faixas_etarias');
            faixasGlobais = await res.json();
            const container = document.getElementById('container-faixas-reserva');
            container.innerHTML = '';
            faixasGlobais.forEach(f => {
                let div = document.createElement('div');
                div.style = "flex: 1; min-width: 140px;";
                div.innerHTML = `
                    <label style="font-size: 12px; display:block;">${escaparHtml(f.nome)} <br>(+ R$ ${f.valor_adicional.toFixed(2)})</label>
                    <input type="number" class="faixa-input" data-id="${f.id}" value="0" min="0" style="width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 4px;">
                `;
                container.appendChild(div);
            });
        }

        async function criarReserva(e) {
            e.preventDefault();
            const composicao = [];
            document.querySelectorAll('.faixa-input').forEach(inp => {
                composicao.push({ 
                    faixa_id: parseInt(inp.getAttribute('data-id')), 
                    quantidade: parseInt(inp.value) 
                });
            });

            const res = await fetch('/api/reservas', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    hospede_id: parseInt(document.getElementById('r-hospede-id').value),
                    quarto_numero: document.getElementById('r-quarto-num').value,
                    check_in: document.getElementById('r-checkin').value,
                    check_out: document.getElementById('r-checkout').value,
                    diarias: parseInt(document.getElementById('r-diarias').value),
                    composicao: composicao
                })
            });
            const data = await res.json();
            if(res.ok) {
                alert(`Reserva efetuada com sucesso! Valor Total: R$ ${data.valor_total.toFixed(2)}`);
                document.getElementById('form-reserva').reset();
                carregarReservas();
            } else {
                alert('Erro ao criar reserva: ' + (data.erro || 'Erro desconhecido'));
            }
        }

        async function carregarReservas() {
            const res = await fetch('/api/reservas');
            const data = await res.json();
            const tbody = document.getElementById('tabela-reservas');
            tbody.innerHTML = '';
            data.forEach(r => {
                let tr = document.createElement('tr');
                tr.innerHTML = `
                    <td>${r.id}</td>
                    <td>${r.hospede_id} (${escaparHtml(r.hospede_nome) || 'N/D'})</td>
                    <td><b>${escaparHtml(r.quarto_numero)}</b></td>
                    <td>${escaparHtml(r.check_in)} até ${escaparHtml(r.check_out)}</td>
                    <td>${escaparHtml(r.detalhes_pessoas)}</td>
                    <td>${r.diarias}</td>
                    <td>R$ ${r.valor_total.toFixed(2)}</td>
                    <td><span class="badge ${r.status_pagamento.toLowerCase()}">${escaparHtml(r.status_pagamento)}</span></td>
                `;
                tbody.appendChild(tr);
            });
        }

        async function carregarEstoque() {
            const res = await fetch('/api/estoque');
            const data = await res.json();
            const tbody = document.getElementById('tabela-estoque');
            tbody.innerHTML = '';
            data.forEach(i => {
                let tr = document.createElement('tr');
                tr.innerHTML = `
                    <td><b>${escaparHtml(i.item)}</b></td>
                    <td>${escaparHtml(i.categoria)}</td>
                    <td>${i.quantidade}</td>
                    <td>R$ ${i.preco_unitario.toFixed(2)}</td>
                    <td><button class="btn btn-danger" onclick="deletarEstoque(${i.id})">Excluir</button></td>
                `;
                tbody.appendChild(tr);
            });
        }

        async function criarEstoque(e) {
            e.preventDefault();
            await fetch('/api/estoque', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    item: document.getElementById('e-item').value,
                    categoria: document.getElementById('e-cat').value,
                    quantidade: parseInt(document.getElementById('e-qtd').value),
                    preco_unitario: parseFloat(document.getElementById('e-preco').value)
                })
            });
            document.getElementById('form-estoque').reset();
            carregarEstoque();
        }

        async function deletarEstoque(id) {
            if(!confirm('Remover item?')) return;
            await fetch(`/api/estoque/${id}`, { method: 'DELETE' });
            carregarEstoque();
        }

        async function carregarFinanceiro() {
            const res = await fetch('/api/financeiro');
            const data = await res.json();
            const tbody = document.getElementById('tabela-financeiro');
            tbody.innerHTML = '';
            data.forEach(f => {
                let tr = document.createElement('tr');
                tr.innerHTML = `
                    <td>${escaparHtml(f.data)}</td>
                    <td><b>${escaparHtml(f.tipo)}</b></td>
                    <td>${escaparHtml(f.descricao)}</td>
                    <td>${escaparHtml(f.categoria)}</td>
                    <td style="color: ${f.tipo === 'ENTRADA' ? 'green' : 'red'}; font-weight: bold;">
                        R$ ${f.valor.toFixed(2)}
                    </td>
                `;
                tbody.appendChild(tr);
            });
        }

        async function criarFinanceiro(e) {
            e.preventDefault();
            await fetch('/api/financeiro', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    tipo: document.getElementById('f-tipo').value,
                    descricao: document.getElementById('f-desc').value,
                    valor: parseFloat(document.getElementById('f-valor').value),
                    categoria: document.getElementById('f-cat').value
                })
            });
            document.getElementById('form-financeiro').reset();
            carregarFinanceiro();
        }

        async function carregarOrdens() {
            const res = await fetch('/api/ordens');
            const data = await res.json();
            const tbody = document.getElementById('tabela-ordens');
            tbody.innerHTML = '';
            data.forEach(o => {
                let tr = document.createElement('tr');
                tr.innerHTML = `
                    <td>${o.id}</td>
                    <td><b>${escaparHtml(o.quarto)}</b></td>
                    <td>${escaparHtml(o.tipo)}</td>
                    <td>${escaparHtml(o.descricao)}</td>
                    <td><span class="badge ${o.status === 'CONCLUIDA' ? 'disponivel' : 'pendente'}">${escaparHtml(o.status)}</span></td>
                    <td>${o.status !== 'CONCLUIDA' ? `<button class="btn btn-success" onclick="concluirOrdem(${o.id})">Concluir</button>` : '-'}</td>
                `;
                tbody.appendChild(tr);
            });
        }

        async function criarOrdem(e) {
            e.preventDefault();
            await fetch('/api/ordens', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    quarto: document.getElementById('os-quarto').value,
                    tipo: document.getElementById('os-tipo').value,
                    descricao: document.getElementById('os-desc').value
                })
            });
            document.getElementById('form-ordem').reset();
            carregarOrdens();
        }

        async function concluirOrdem(id) {
            await fetch(`/api/ordens/${id}/status`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ status: 'CONCLUIDA' })
            });
            carregarOrdens();
        }

        async function carregarRelatorios() {
            const res = await fetch('/api/relatorios');
            const data = await res.json();
            const grid = document.getElementById('dados-relatorio');
            grid.innerHTML = `
                <div class="metric-card"><h5>Total de Quartos</h5><p>${data.total_quartos}</p></div>
                <div class="metric-card"><h5>Quartos Ocupados</h5><p>${data.quartos_ocupados}</p></div>
                <div class="metric-card"><h5>Taxa de Ocupação</h5><p>${data.taxa_ocupacao}%</p></div>
                <div class="metric-card"><h5>ADR (Diária Média)</h5><p>R$ ${data.adr.toFixed(2)}</p></div>
                <div class="metric-card"><h5>RevPAR</h5><p>R$ ${data.revpar.toFixed(2)}</p></div>
                <div class="metric-card" style="border-left-color: #2ecc71;"><h5>Receita Hospedagem Total</h5><p style="color:#2ecc71;">R$ ${data.receita_total.toFixed(2)}</p></div>
            `;
        }

        function preencherTemplateWhatsApp() {
            const temp = document.getElementById('wa-template').value;
            document.getElementById('wa-msg').value = temp;
        }

        function enviarWhatsApp() {
            let tel = document.getElementById('wa-tel').value.replace(/\D/g, '');
            let msg = encodeURIComponent(document.getElementById('wa-msg').value);
            if(tel.length < 10) { alert('Digite um telefone válido com DDD.'); return; }
            window.open(`https://wa.me/${tel}?text=${msg}`, '_blank');
        }

        renderizarMenu();
        switchTab('quartos');
    </script>
</body>
</html>'''

if __name__ == '__main__':
    init_db()
    app.run(host=os.getenv('HOST','0.0.0.0'), port=int(os.getenv('PORT','5000')), debug=os.getenv('FLASK_DEBUG','0').lower() in ('1','true','yes'))