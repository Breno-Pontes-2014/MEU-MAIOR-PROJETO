import os
import datetime
import json
import hashlib
import secrets
import time
import sqlite3
import urllib.parse
import urllib.request
import jwt
from functools import wraps
from flask import Flask, request, jsonify, render_template_string, redirect, url_for, session, g
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:
    psycopg = None
    dict_row = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'hotel.db')
DATABASE_URL = os.getenv('DATABASE_URL', '').strip()
JWT_SECRET_FILE = os.path.join(BASE_DIR, '.jwt_secret')
TEMPLATES_DIR = BASE_DIR

app = Flask(
    __name__,
    template_folder=TEMPLATES_DIR
)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

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

class DBCursor:
    def __init__(self, connection, cursor):
        self.connection = connection
        self.cursor = cursor

    def _sql(self, sql):
        if self.connection.is_postgres:
            sql = sql.replace('INTEGER PRIMARY KEY AUTOINCREMENT', 'BIGSERIAL PRIMARY KEY')
            sql = sql.replace('AUTOINCREMENT', '')
            sql = sql.replace('?', '%s')
        return sql

    def execute(self, sql, params=None):
        self.cursor.execute(self._sql(sql), params or ())
        return self

    def executemany(self, sql, seq_of_params):
        self.cursor.executemany(self._sql(sql), seq_of_params)
        return self

    def fetchone(self):
        return self.cursor.fetchone()

    def fetchall(self):
        return self.cursor.fetchall()

    @property
    def lastrowid(self):
        if not self.connection.is_postgres:
            return self.cursor.lastrowid
        row = self.connection.raw.execute('SELECT LASTVAL() AS last_id').fetchone()
        if not row:
            return None
        try:
            return row['last_id']
        except (TypeError, KeyError, IndexError):
            return row[0]

class DBConnection:
    def __init__(self, raw, is_postgres=False):
        self.raw = raw
        self.is_postgres = is_postgres

    def cursor(self):
        return DBCursor(self, self.raw.cursor())

    def execute(self, sql, params=None):
        return self.cursor().execute(sql, params)

    def commit(self):
        self.raw.commit()

    def rollback(self):
        self.raw.rollback()

    def close(self):
        self.raw.close()

def get_db():
    if DATABASE_URL:
        if psycopg is None:
            raise RuntimeError('PostgreSQL foi configurado em DATABASE_URL, mas psycopg não está instalado. Execute: pip install "psycopg[binary]"')
        conn = psycopg.connect(
            DATABASE_URL,
            row_factory=dict_row,
            connect_timeout=10
        )
        conn.execute("SET statement_timeout = '30s'")
        return DBConnection(conn, is_postgres=True)

    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    conn.execute('PRAGMA busy_timeout = 15000')
    return DBConnection(conn, is_postgres=False)


TENANT_TABLES = ['quartos','hospedes','faixas_etarias','reservas','estoque','fluxo_caixa','ordens_servico']
PUBLIC_API_ENDPOINTS_WHEN_EXPIRED = {'api_planos','api_assinatura','api_solicitar_plano'}
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

ROLE_LABELS = {
    'platform_admin': 'Administrador do SaaS',
    'admin': 'Administrador do Hotel',
    'gerente': 'Gerente',
    'recepcao': 'Recepção',
    'limpeza': 'Limpeza',
    'manutencao': 'Manutenção',
    'financeiro': 'Financeiro'
}

ROLE_PERMISSIONS = {
    'admin': {'*'},
    'gerente': {'rooms.view','rooms.manage','guests.view','guests.manage','categories.view','categories.manage','reservations.view','reservations.manage','reservations.pay','stock.view','stock.manage','finance.view','finance.manage','orders.view','orders.manage','services.view','services.manage','requests.view','requests.manage','reports.view','whatsapp.use'},
    'recepcao': {'rooms.view','guests.view','guests.manage','reservations.view','reservations.manage','reservations.pay','orders.view','orders.manage','services.view','requests.view','requests.manage','whatsapp.use'},
    'limpeza': {'rooms.view','orders.view','orders.manage','requests.view','requests.manage'},
    'manutencao': {'rooms.view','orders.view','orders.manage','requests.view'},
    'financeiro': {'rooms.view','guests.view','reservations.view','reservations.pay','finance.view','finance.manage','requests.view','requests.manage','reports.view'}
}

ENDPOINT_PERMISSIONS = {
    'listar_quartos':'rooms.view','criar_quarto':'rooms.manage','criar_quartos_lote':'rooms.manage','editar_quarto':'rooms.manage','deletar_quarto':'rooms.manage',
    'listar_hospedes':'guests.view','criar_hospede':'guests.manage','editar_hospede':'guests.manage',
    'listar_faixas':'categories.view','criar_faixa':'categories.manage','editar_faixa':'categories.manage','deletar_faixa':'categories.manage',
    'listar_reservas':'reservations.view','criar_reserva':'reservations.manage','editar_reserva':'reservations.manage','cancelar_reserva':'reservations.manage','marcar_pagamento_reserva':'reservations.pay',
    'gerenciar_estoque':'stock.manage','editar_estoque':'stock.manage','deletar_estoque':'stock.manage',
    'gerenciar_financeiro':'finance.manage','editar_financeiro':'finance.manage',
    'gerenciar_ordens':'orders.manage','atualizar_ordem':'orders.manage','editar_ordem':'orders.manage','deletar_ordem':'orders.manage',
    'relatorios_gerenciais':'reports.view',
    'api_integracoes':'integrations.view','salvar_integracoes':'integrations.manage','pesquisar_maps':'integrations.manage',
    'criar_checkout_asaas':'subscription.manage','api_assinatura':'subscription.view','api_assinatura_limites':'subscription.view','api_solicitar_plano':'subscription.manage',
    'listar_usuarios_hotel':'team.view','criar_usuario_hotel':'team.manage','editar_usuario_hotel':'team.manage','desativar_usuario_hotel':'team.manage',
    'listar_servicos':'services.view','criar_servico':'services.manage','editar_servico':'services.manage','deletar_servico':'services.manage',
    'listar_pedidos':'requests.view','criar_pedido':'requests.manage','atualizar_pedido_status':'requests.manage','marcar_pagamento_pedido':'requests.manage'
}

def can(role, permission):
    if role == 'platform_admin':
        return True
    perms = ROLE_PERMISSIONS.get(role, set())
    return '*' in perms or permission in perms

def senha_compat(password_hash, password):
    if isinstance(password_hash, str) and password_hash.startswith('SAASPBKDF2$'):
        import base64, hmac
        try:
            _, iterations, salt_b64, digest_b64 = password_hash.split('$', 3)
            salt = base64.urlsafe_b64decode(salt_b64.encode('ascii'))
            esperado = base64.urlsafe_b64decode(digest_b64.encode('ascii'))
            derivado = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, int(iterations))
            return hmac.compare_digest(derivado, esperado)
        except Exception:
            return False
    try:
        return check_password_hash(password_hash, password)
    except Exception:
        return False

def client_ip():
    return (request.remote_addr or 'unknown').strip()


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
    if cursor.connection.is_postgres:
        row = cursor.execute(
            'SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = ? AND column_name = ? LIMIT 1',
            (table, column_name)
        ).fetchone()
        if row is None:
            cursor.execute(f'ALTER TABLE {table} ADD COLUMN {column_def}')
    else:
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

def get_hotel_integracoes(conn, hotel_id):
    row = conn.execute('SELECT * FROM hotel_integracoes WHERE hotel_id=? LIMIT 1',(hotel_id,)).fetchone()
    return dict(row) if row else None

def normalizar_url(valor):
    valor = str(valor or '').strip()
    if not valor:
        return None
    if len(valor) > 1000:
        raise ValueError('URL muito longa.')
    parsed = urllib.parse.urlparse(valor)
    if parsed.scheme != 'https' or not parsed.netloc:
        raise ValueError('Informe uma URL válida começando por https://')
    return valor

def maps_embed_url(integracao):
    key = os.getenv('GOOGLE_MAPS_API_KEY','').strip()
    if not key:
        return None
    place_id = (integracao.get('maps_place_id') or '').strip()
    endereco = (integracao.get('endereco') or '').strip()
    query = f'place_id:{place_id}' if place_id else endereco
    if not query:
        return None
    return 'https://www.google.com/maps/embed/v1/place?' + urllib.parse.urlencode({'key':key,'q':query})

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
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "script-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "connect-src 'self'; "
        "frame-src https://www.google.com https://www.google.com/maps/; "
        "base-uri 'self'; form-action 'self'; object-src 'none'; frame-ancestors 'none'"
    )
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    if request.is_secure or request.headers.get('X-Forwarded-Proto','').lower()=='https':
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

def ensure_servicos_padrao(cursor, hotel_id):
    padrao = [
        ('Toalha extra','Quarto',10.00,'unidade'),
        ('Água mineral','A&B',5.00,'unidade'),
        ('Café da manhã','A&B',25.00,'pessoa'),
        ('Lavanderia','Lavanderia',20.00,'peça'),
        ('Transfer','Transporte',80.00,'trajeto'),
        ('Almoço','A&B',35.00,'pessoa'),
        ('Jantar','A&B',35.00,'pessoa'),
        ('Outros','Diversos',0.00,'unidade')
    ]
    for nome,categoria,preco,unidade in padrao:
        if not cursor.execute('SELECT id FROM servicos WHERE hotel_id=? AND nome=? LIMIT 1',(hotel_id,nome)).fetchone():
            cursor.execute('INSERT INTO servicos (hotel_id,nome,categoria,preco,unidade,ativo) VALUES (?,?,?,?,?,1)',(hotel_id,nome,categoria,preco,unidade))

def ensure_platform_admin(cursor):
    username=os.getenv('SAAS_ADMIN_INITIAL_USERNAME','').strip()
    password=os.getenv('SAAS_ADMIN_INITIAL_PASSWORD','')
    if not username or not password:
        return
    if cursor.execute('SELECT id FROM usuarios WHERE username=? LIMIT 1',(username,)).fetchone():
        return
    erro=validate_password(password)
    if erro:
        raise RuntimeError('SAAS_ADMIN_INITIAL_PASSWORD não atende à política de segurança.')
    cursor.execute('INSERT INTO usuarios (username,nome,password,role,hotel_id,ativo) VALUES (?,?,?,?,?,1)',
                   (username,username,generate_password_hash(password,method='pbkdf2:sha256'),'platform_admin',None))

def init_db():
    conn=get_db()
    cursor=conn.cursor()
    try:
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS hoteis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT NOT NULL,
                data_cadastro TEXT NOT NULL,
                local TEXT,
                bloqueado INTEGER NOT NULL DEFAULT 0,
                bloqueado_em TEXT,
                bloqueio_motivo TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                nome TEXT,
                password TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'recepcao',
                hotel_id INTEGER,
                email TEXT,
                ativo INTEGER NOT NULL DEFAULT 1,
                ultimo_login TEXT,
                FOREIGN KEY (hotel_id) REFERENCES hoteis(id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tipos_quarto (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT NOT NULL,
                preco_diaria REAL NOT NULL,
                hotel_id INTEGER,
                ativo INTEGER NOT NULL DEFAULT 1,
                FOREIGN KEY (hotel_id) REFERENCES hoteis(id)
            )
        ''')
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
                pago_em TEXT,
                pago_por INTEGER,
                financeiro_id INTEGER,
                criada_por INTEGER,
                FOREIGN KEY (hotel_id) REFERENCES hoteis(id)
            )
        ''')
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
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS fluxo_caixa (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tipo TEXT NOT NULL,
                descricao TEXT NOT NULL,
                valor REAL NOT NULL,
                categoria TEXT NOT NULL,
                data TEXT NOT NULL,
                hotel_id INTEGER,
                origem_tipo TEXT,
                origem_id INTEGER,
                forma_pagamento TEXT,
                criado_por INTEGER,
                FOREIGN KEY (hotel_id) REFERENCES hoteis(id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ordens_servico (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                quarto TEXT NOT NULL,
                tipo TEXT NOT NULL,
                descricao TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'PENDENTE',
                hotel_id INTEGER,
                quarto_id INTEGER,
                hospede_id INTEGER,
                solicitante_id INTEGER,
                responsavel_id INTEGER,
                prioridade TEXT NOT NULL DEFAULT 'NORMAL',
                aberta_em TEXT,
                concluida_em TEXT,
                valor REAL NOT NULL DEFAULT 0,
                FOREIGN KEY (hotel_id) REFERENCES hoteis(id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS hotel_integracoes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hotel_id INTEGER NOT NULL UNIQUE,
                booking_url TEXT,
                airbnb_url TEXT,
                expedia_url TEXT,
                hoteis_url TEXT,
                website_url TEXT,
                maps_place_id TEXT,
                maps_url TEXT,
                maps_nome TEXT,
                endereco TEXT,
                latitude REAL,
                longitude REAL,
                atualizado_em TEXT NOT NULL,
                FOREIGN KEY (hotel_id) REFERENCES hoteis(id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS webhook_eventos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                provider TEXT NOT NULL,
                event_id TEXT NOT NULL UNIQUE,
                event_type TEXT,
                hotel_id INTEGER,
                payload TEXT NOT NULL,
                recebido_em TEXT NOT NULL,
                processado_em TEXT,
                status TEXT NOT NULL DEFAULT 'RECEBIDO',
                erro TEXT,
                FOREIGN KEY (hotel_id) REFERENCES hoteis(id)
            )
        ''')
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
                checkout_externo TEXT,
                atualizado_em TEXT NOT NULL,
                FOREIGN KEY (hotel_id) REFERENCES hoteis(id),
                FOREIGN KEY (plano_id) REFERENCES planos(id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS servicos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hotel_id INTEGER NOT NULL,
                nome TEXT NOT NULL,
                categoria TEXT NOT NULL DEFAULT 'Diversos',
                preco REAL NOT NULL DEFAULT 0,
                unidade TEXT NOT NULL DEFAULT 'unidade',
                ativo INTEGER NOT NULL DEFAULT 1,
                FOREIGN KEY (hotel_id) REFERENCES hoteis(id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS pedidos_hospede (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hotel_id INTEGER NOT NULL,
                reserva_id INTEGER,
                quarto_id INTEGER,
                hospede_id INTEGER,
                servico_id INTEGER,
                item TEXT NOT NULL,
                descricao TEXT,
                quantidade REAL NOT NULL DEFAULT 1,
                preco_unitario REAL NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'ABERTO',
                status_pagamento TEXT NOT NULL DEFAULT 'PENDENTE',
                solicitado_em TEXT NOT NULL,
                criado_por INTEGER,
                pago_em TEXT,
                pago_por INTEGER,
                financeiro_id INTEGER,
                FOREIGN KEY (hotel_id) REFERENCES hoteis(id)
            )
        ''')

        for table,coldef in [
            ('hoteis','bloqueado INTEGER NOT NULL DEFAULT 0'),('hoteis','bloqueado_em TEXT'),('hoteis','bloqueio_motivo TEXT'),
            ('usuarios','nome TEXT'),('usuarios','email TEXT'),('usuarios','ativo INTEGER NOT NULL DEFAULT 1'),('usuarios','ultimo_login TEXT'),
            ('reservas','pago_em TEXT'),('reservas','pago_por INTEGER'),('reservas','financeiro_id INTEGER'),('reservas','criada_por INTEGER'),
            ('fluxo_caixa','origem_tipo TEXT'),('fluxo_caixa','origem_id INTEGER'),('fluxo_caixa','forma_pagamento TEXT'),('fluxo_caixa','criado_por INTEGER'),
            ('ordens_servico','quarto_id INTEGER'),('ordens_servico','hospede_id INTEGER'),('ordens_servico','solicitante_id INTEGER'),('ordens_servico','responsavel_id INTEGER'),
            ('ordens_servico','prioridade TEXT NOT NULL DEFAULT \'NORMAL\''),('ordens_servico','aberta_em TEXT'),('ordens_servico','concluida_em TEXT'),('ordens_servico','valor REAL NOT NULL DEFAULT 0'),
            ('assinaturas','checkout_externo TEXT')
        ]:
            try:
                add_column_if_missing(cursor,table,coldef)
            except Exception:
                pass

        ensure_planos(cursor)
        ensure_platform_admin(cursor)

        hotels=cursor.execute('SELECT id FROM hoteis ORDER BY id').fetchall()
        for row in hotels:
            hid=row['id']
            qtd=cursor.execute('SELECT COUNT(*) AS total FROM faixas_etarias WHERE hotel_id=?',(hid,)).fetchone()['total']
            if qtd==0:
                cursor.executemany('INSERT INTO faixas_etarias (nome,idade_min,idade_max,valor_adicional,hotel_id) VALUES (?,?,?,?,?)',
                                   [('Criança (até 11 anos)',0,11,0.0,hid),('Adulto',12,59,0.0,hid),('Idoso',60,120,0.0,hid)])
            ensure_subscription_for_hotel(cursor,hid)
            ensure_servicos_padrao(cursor,hid)

        for table in TENANT_TABLES + ['servicos','pedidos_hospede']:
            cursor.execute(f'CREATE INDEX IF NOT EXISTS idx_{table}_hotel_id ON {table}(hotel_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_usuarios_hotel_id ON usuarios(hotel_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_reservas_quarto_datas ON reservas(hotel_id,quarto_numero,check_in,check_out)')
        cursor.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_servicos_hotel_nome ON servicos(hotel_id,nome)')
        conn.commit()
    finally:
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
                user=conn.execute('SELECT id,username,nome,role,hotel_id,ativo,email FROM usuarios WHERE id=? LIMIT 1',(session['user_id'],)).fetchone()
            if not user:
                auth_header=request.headers.get('Authorization','')
                token=auth_header[7:].strip() if auth_header.startswith('Bearer ') else None
                if not token:
                    return jsonify({'erro':'Token de acesso não fornecido.'}),401
                try:
                    data=jwt.decode(token,JWT_SECRET,algorithms=['HS256'])
                except jwt.ExpiredSignatureError:
                    return jsonify({'erro':'Token expirado.'}),401
                except jwt.InvalidTokenError:
                    return jsonify({'erro':'Token inválido.'}),401
                user=conn.execute('SELECT id,username,nome,role,hotel_id,ativo,email FROM usuarios WHERE id=? OR username=? LIMIT 1',(data.get('user_id'),data.get('username'))).fetchone()

            if not user:
                return jsonify({'erro':'Usuário não encontrado.'}),401
            if not int(user['ativo'] or 0):
                return jsonify({'erro':'Seu usuário está bloqueado. Procure o administrador do hotel.'}),403

            role=user['role']
            if role=='platform_admin':
                g.current_user_id=user['id']; g.current_user=user['username']; g.current_user_name=user['nome'] or user['username']
                g.current_role=role; g.hotel_id=None; g.hotel=None; g.subscription=None
            else:
                hotel_id=user['hotel_id']
                if not hotel_id:
                    return jsonify({'erro':'Usuário sem hotel vinculado.'}),403
                hotel=conn.execute('SELECT id,nome,local,bloqueado,bloqueio_motivo FROM hoteis WHERE id=? LIMIT 1',(hotel_id,)).fetchone()
                if not hotel:
                    return jsonify({'erro':'Hotel vinculado não encontrado.'}),403
                if int(hotel['bloqueado'] or 0):
                    return jsonify({'erro':'O acesso deste hotel foi suspenso pela administração do SaaS.','codigo':'HOTEL_BLOQUEADO','motivo':hotel['bloqueio_motivo'] or 'Acesso suspenso.'}),423
                g.current_user_id=user['id']; g.current_user=user['username']; g.current_user_name=user['nome'] or user['username']
                g.current_role=role; g.hotel_id=hotel_id; g.hotel=hotel
                g.subscription=get_subscription(conn,hotel_id)
                if request.endpoint not in PUBLIC_API_ENDPOINTS_WHEN_EXPIRED and (not g.subscription or not g.subscription['ativo']):
                    return subscription_blocked_response()

            required=ENDPOINT_PERMISSIONS.get(request.endpoint)
            if required and not can(role,required):
                return jsonify({'erro':'Seu perfil não possui permissão para esta operação.'}),403

            return f(user['username'],role,*args,**kwargs)
        finally:
            conn.close()
    return decorated

@app.route('/')
def page_root():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method=='POST':
        username=request.form.get('username','').strip()
        password=request.form.get('password','')
        if not check_csrf():
            return render_template_string(LOGIN_TEMPLATE,erro='Sessão expirada. Recarregue a página.',csrf_token=csrf_token())
        lock_key=f'{client_ip()}::{username.lower()}'
        if login_is_locked(lock_key):
            return render_template_string(LOGIN_TEMPLATE,erro='Muitas tentativas. Tente novamente em alguns minutos.',csrf_token=csrf_token())
        conn=get_db()
        try:
            user=conn.execute('SELECT * FROM usuarios WHERE username=? LIMIT 1',(username,)).fetchone()
            if user and senha_compat(user['password'],password):
                if not int(user['ativo'] or 0):
                    register_login_failure(lock_key)
                    return render_template_string(LOGIN_TEMPLATE,erro='Este usuário está bloqueado.',csrf_token=csrf_token())
                if user['role']!='platform_admin':
                    hotel=conn.execute('SELECT id,nome,bloqueado FROM hoteis WHERE id=?',(user['hotel_id'],)).fetchone() if user['hotel_id'] else None
                    if not hotel:
                        return render_template_string(LOGIN_TEMPLATE,erro='Hotel deste usuário não foi encontrado.',csrf_token=csrf_token())
                    if int(hotel['bloqueado'] or 0):
                        return render_template_string(LOGIN_TEMPLATE,erro='O acesso deste hotel está suspenso pelo administrador do SaaS.',csrf_token=csrf_token())
                clear_login_failures(lock_key)
                if isinstance(user['password'],str) and user['password'].startswith('SAASPBKDF2$'):
                    conn.execute('UPDATE usuarios SET password=? WHERE id=?',(generate_password_hash(password,method='pbkdf2:sha256'),user['id']))
                conn.execute('UPDATE usuarios SET ultimo_login=? WHERE id=?',(datetime.datetime.utcnow().isoformat(),user['id']))
                conn.commit()
                session.clear(); session.permanent=True
                session['user_id']=user['id']; session['user']=user['username']; session['role']=user['role']; session['hotel_id']=user['hotel_id']
                csrf_token()
                return redirect(url_for('dashboard'))
            register_login_failure(lock_key)
            return render_template_string(LOGIN_TEMPLATE,erro='Usuário ou senha inválidos.',csrf_token=csrf_token())
        finally:
            conn.close()
    return render_template_string(LOGIN_TEMPLATE,csrf_token=csrf_token())

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        hotel_nome = request.form.get('hotel_nome', '').strip()
        if not check_csrf():
            return render_template_string(REGISTER_TEMPLATE, erro='Sessão expirada. Recarregue a página.', csrf_token=csrf_token())
        senha_erro = validate_password(password)
        if senha_erro:
            return render_template_string(REGISTER_TEMPLATE, erro=senha_erro, csrf_token=csrf_token())

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

            ensure_subscription_for_hotel(cursor,hotel_id)
            conn.commit()
            conn.close()
            return render_template_string(LOGIN_TEMPLATE, sucesso="Hotel e Usuário cadastrados com sucesso! Faça seu login.",csrf_token=csrf_token())

        except Exception:
            app.logger.exception('Falha no cadastro de hotel')
            conn.rollback()
            conn.close()
            return render_template_string(REGISTER_TEMPLATE, erro='Não foi possível concluir o cadastro. Verifique os dados e tente novamente.',csrf_token=csrf_token())

    return render_template_string(REGISTER_TEMPLATE,csrf_token=csrf_token())

@app.route('/logout',methods=['GET','POST'])
def logout():
    if request.method=='POST' and not check_csrf():
        return 'Token CSRF ausente ou inválido.',403
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn=get_db()
    try:
        user=conn.execute('SELECT id,username,nome,role,hotel_id,ativo,email FROM usuarios WHERE id=? LIMIT 1',(session['user_id'],)).fetchone()
        if not user or not int(user['ativo'] or 0):
            session.clear()
            return redirect(url_for('login'))
        hotel=None; assinatura=None
        if user['hotel_id']:
            hotel=conn.execute('SELECT id,nome,local,bloqueado,bloqueio_motivo FROM hoteis WHERE id=?',(user['hotel_id'],)).fetchone()
            assinatura=get_subscription(conn,user['hotel_id'])
            if not hotel or int(hotel['bloqueado'] or 0):
                session.clear()
                return render_template_string(LOGIN_TEMPLATE,erro='O acesso deste hotel está suspenso.',csrf_token=csrf_token())
            if user['role']!='platform_admin' and (not assinatura or not assinatura['ativo']):
                return render_template_string(LOGIN_TEMPLATE,erro='A assinatura deste hotel está inativa ou expirada.',csrf_token=csrf_token())
        contexto={'id':user['id'],'username':user['username'],'nome':user['nome'] or user['username'],'role':user['role'],
                  'role_label':ROLE_LABELS.get(user['role'],user['role']),'hotel_id':user['hotel_id'],
                  'hotel_nome':hotel['nome'] if hotel else None,'hotel_local':hotel['local'] if hotel else None,
                  'assinatura':assinatura}
        return render_template_string(DASHBOARD_TEMPLATE,csrf_token=csrf_token(),contexto_usuario=contexto)
    finally:
        conn.close()

def sincronizar_status_quartos(conn, hotel_id):
    if not hotel_id: return
    hoje=datetime.date.today().isoformat()
    quartos=conn.execute('SELECT id,numero,status FROM quartos WHERE hotel_id=?',(hotel_id,)).fetchall()
    for q in quartos:
        if q['status']=='MANUTENCAO':
            continue
        ocupado=conn.execute("SELECT id FROM reservas WHERE hotel_id=? AND quarto_numero=? AND status<>'CANCELADA' AND check_in<=? AND check_out>? LIMIT 1",
                             (hotel_id,q['numero'],hoje,hoje)).fetchone()
        if ocupado:
            status='OCUPADO'
        else:
            futuro=conn.execute("SELECT id FROM reservas WHERE hotel_id=? AND quarto_numero=? AND status<>'CANCELADA' AND check_in>? ORDER BY check_in LIMIT 1",
                                (hotel_id,q['numero'],hoje)).fetchone()
            status='RESERVADO' if futuro else 'DISPONIVEL'
        conn.execute('UPDATE quartos SET status=? WHERE id=? AND hotel_id=?',(status,q['id'],hotel_id))

def gerar_numeros_quartos(quantidade,inicial,por_andar):
    if por_andar>0:
        numeros=[]; andar,pos=divmod(inicial,100)
        for _ in range(quantidade):
            numeros.append(str(andar*100+pos)); pos+=1
            if pos>por_andar: andar+=1; pos=1
        return numeros
    return [str(inicial+i) for i in range(quantidade)]

def composicao_reserva(conn,hotel_id,composicao):
    faixas={f['id']:f for f in conn.execute('SELECT * FROM faixas_etarias WHERE hotel_id=?',(hotel_id,)).fetchall()}
    extra=0.0; partes=[]
    for item in composicao if isinstance(composicao,list) else []:
        try: fid=int(item.get('faixa_id',0)); qtd=int(item.get('quantidade',0))
        except (TypeError,ValueError): continue
        if qtd<=0 or fid not in faixas: continue
        extra+=float(faixas[fid]['valor_adicional'] or 0)*qtd
        partes.append(f"{qtd}x {faixas[fid]['nome']}")
    return extra,', '.join(partes) or 'Reserva Padrão'

def reserva_conflito(conn,hotel_id,quarto_numero,check_in,check_out,ignorar_id=None):
    sql="SELECT id FROM reservas WHERE hotel_id=? AND quarto_numero=? AND status<>'CANCELADA' AND check_in<? AND check_out>?"
    params=[hotel_id,quarto_numero,check_out,check_in]
    if ignorar_id is not None:
        sql+=" AND id<>?"; params.append(ignorar_id)
    return conn.execute(sql,tuple(params)).fetchone()

def sincronizar_status_quartos(conn,hotel_id):
    if not hotel_id: return
    hoje=datetime.date.today().isoformat()
    for q in conn.execute('SELECT id,numero,status FROM quartos WHERE hotel_id=?',(hotel_id,)).fetchall():
        if q['status']=='MANUTENCAO': continue
        ocupado=conn.execute("SELECT id FROM reservas WHERE hotel_id=? AND quarto_numero=? AND status<>'CANCELADA' AND check_in<=? AND check_out>? LIMIT 1",(hotel_id,q['numero'],hoje,hoje)).fetchone()
        if ocupado:
            status='OCUPADO'
        else:
            futuro=conn.execute("SELECT id FROM reservas WHERE hotel_id=? AND quarto_numero=? AND status<>'CANCELADA' AND check_in>? ORDER BY check_in LIMIT 1",(hotel_id,q['numero'],hoje)).fetchone()
            status='RESERVADO' if futuro else 'DISPONIVEL'
        conn.execute('UPDATE quartos SET status=? WHERE id=? AND hotel_id=?',(status,q['id'],hotel_id))

def registrar_entrada_reserva(conn,reserva_id,forma_pagamento='NÃO INFORMADO'):
    r=conn.execute('SELECT * FROM reservas WHERE id=? AND hotel_id=?',(reserva_id,g.hotel_id)).fetchone()
    if not r: raise ValueError('Reserva não encontrada.')
    if r['financeiro_id']: return r['financeiro_id']
    cur=conn.cursor()
    cur.execute('INSERT INTO fluxo_caixa (tipo,descricao,valor,categoria,data,hotel_id,origem_tipo,origem_id,forma_pagamento,criado_por) VALUES (?,?,?,?,?,?,?,?,?,?)',
                ('ENTRADA',f"Reserva do quarto {r['quarto_numero']} - {r['check_in']} a {r['check_out']}",float(r['valor_total'] or 0),'Hospedagem',datetime.date.today().isoformat(),g.hotel_id,'RESERVA',r['id'],forma_pagamento,g.current_user_id))
    fid=cur.lastrowid
    conn.execute("UPDATE reservas SET financeiro_id=?,pago_em=?,pago_por=?,status_pagamento='PAGO' WHERE id=? AND hotel_id=?",(fid,datetime.datetime.utcnow().isoformat(),g.current_user_id,reserva_id,g.hotel_id))
    return fid

@app.route('/api/quartos', methods=['GET'])
@token_required
def listar_quartos(current_user,role):
    conn=get_db()
    try:
        sincronizar_status_quartos(conn,g.hotel_id); conn.commit()
        return jsonify([dict(x) for x in conn.execute('SELECT * FROM quartos WHERE hotel_id=? ORDER BY CAST(numero AS INTEGER),numero',(g.hotel_id,)).fetchall()]),200
    finally: conn.close()

@app.route('/api/quartos', methods=['POST'])
@token_required
def criar_quarto(current_user,role):
    data=request.get_json(silent=True) or {}
    numero=str(data.get('numero') or '').strip()[:30]; tipo=str(data.get('tipo') or 'Standard').strip()[:80]
    try: preco=float(data.get('preco_diaria',0))
    except (TypeError,ValueError): preco=0
    if not numero or preco<=0: return jsonify({'erro':'Número e diária válida são obrigatórios.'}),400
    conn=get_db()
    try:
        if conn.execute('SELECT id FROM quartos WHERE hotel_id=? AND numero=?',(g.hotel_id,numero)).fetchone(): return jsonify({'erro':'Já existe um quarto com este número.'}),409
        ok,erro=enforce_room_quota(conn,1)
        if not ok: return jsonify({'erro':erro}),403
        conn.execute('INSERT INTO quartos (numero,tipo,preco_diaria,status,hotel_id) VALUES (?,?,?,?,?)',(numero,tipo,preco,'DISPONIVEL',g.hotel_id))
        conn.commit(); return jsonify({'mensagem':'Quarto cadastrado com sucesso.'}),201
    finally: conn.close()

@app.route('/api/quartos/lote',methods=['POST'])
@token_required
def criar_quartos_lote(current_user,role):
    data=request.get_json(silent=True) or {}
    try: quantidade=int(data.get('quantidade',0)); inicial=int(data.get('numero_inicial',101)); por_andar=int(data.get('por_andar',0)); preco=float(data.get('preco_diaria',0))
    except (TypeError,ValueError): return jsonify({'erro':'Valores numéricos inválidos.'}),400
    tipo=str(data.get('tipo') or 'Standard').strip()[:80] or 'Standard'
    if quantidade<1 or quantidade>500: return jsonify({'erro':'A quantidade deve ficar entre 1 e 500.'}),400
    if inicial<1: return jsonify({'erro':'O primeiro número deve ser maior que zero.'}),400
    if por_andar<0 or por_andar>99: return jsonify({'erro':'Quartos por andar deve ficar entre 0 e 99.'}),400
    if por_andar>0 and (inicial%100<1 or inicial%100>por_andar): return jsonify({'erro':'Primeiro número incompatível com os quartos por andar.'}),400
    if preco<=0: return jsonify({'erro':'A diária base deve ser maior que zero.'}),400
    numeros=gerar_numeros_quartos(quantidade,inicial,por_andar)
    conn=get_db()
    try:
        existentes=sum(1 for n in numeros if conn.execute('SELECT id FROM quartos WHERE hotel_id=? AND numero=?',(str(n),g.hotel_id)).fetchone())
        ok,erro=enforce_room_quota(conn,quantidade-existentes)
        if not ok: return jsonify({'erro':erro}),403
        criados=0
        for numero in numeros:
            if conn.execute('SELECT id FROM quartos WHERE hotel_id=? AND numero=?',(str(numero),g.hotel_id)).fetchone(): continue
            conn.execute('INSERT INTO quartos (numero,tipo,preco_diaria,status,hotel_id) VALUES (?,?,?,?,?)',(str(numero),tipo,preco,'DISPONIVEL',g.hotel_id)); criados+=1
        conn.commit()
        if not criados: return jsonify({'erro':'Todos esses números de quarto já existem.'}),409
        ignorados=quantidade-criados
        return jsonify({'mensagem':f'{criados} quarto(s) criado(s).'+(f' {ignorados} já existiam e foram mantidos.' if ignorados else ''),'criados':criados,'ignorados':ignorados}),201
    finally: conn.close()

@app.route('/api/quartos/<int:qid>',methods=['PUT'])
@token_required
def editar_quarto(current_user,role,qid):
    data=request.get_json(silent=True) or {}; conn=get_db()
    try:
        q=conn.execute('SELECT * FROM quartos WHERE id=? AND hotel_id=?',(qid,g.hotel_id)).fetchone()
        if not q: return jsonify({'erro':'Quarto não encontrado.'}),404
        numero=str(data.get('numero',q['numero']) or '').strip()[:30]; tipo=str(data.get('tipo',q['tipo']) or '').strip()[:80]
        try: preco=float(data.get('preco_diaria',q['preco_diaria']))
        except (TypeError,ValueError): return jsonify({'erro':'Diária inválida.'}),400
        status=str(data.get('status',q['status']) or 'DISPONIVEL').upper()
        if status not in ('DISPONIVEL','OCUPADO','RESERVADO','MANUTENCAO'): return jsonify({'erro':'Status de quarto inválido.'}),400
        if conn.execute('SELECT id FROM quartos WHERE hotel_id=? AND numero=? AND id<>?',(g.hotel_id,numero,qid)).fetchone(): return jsonify({'erro':'Outro quarto já usa esse número.'}),409
        conn.execute('UPDATE quartos SET numero=?,tipo=?,preco_diaria=?,status=? WHERE id=? AND hotel_id=?',(numero,tipo,preco,status,qid,g.hotel_id))
        conn.commit(); return jsonify({'mensagem':'Quarto atualizado.'}),200
    finally: conn.close()

@app.route('/api/quartos/<int:qid>',methods=['DELETE'])
@token_required
def deletar_quarto(current_user,role,qid):
    conn=get_db()
    try:
        q=conn.execute('SELECT * FROM quartos WHERE id=? AND hotel_id=?',(qid,g.hotel_id)).fetchone()
        if not q: return jsonify({'erro':'Quarto não encontrado.'}),404
        reserva=conn.execute("SELECT id FROM reservas WHERE hotel_id=? AND quarto_numero=? AND status<>'CANCELADA' AND check_out>? LIMIT 1",(g.hotel_id,q['numero'],datetime.date.today().isoformat())).fetchone()
        if reserva: return jsonify({'erro':'Não é possível excluir um quarto com reserva ativa ou futura.'}),409
        conn.execute('DELETE FROM quartos WHERE id=? AND hotel_id=?',(qid,g.hotel_id)); conn.commit()
        return jsonify({'mensagem':'Quarto excluído.'}),200
    finally: conn.close()

@app.route('/api/hospedes',methods=['GET'])
@token_required
def listar_hospedes(current_user,role):
    conn=get_db()
    try: return jsonify([dict(x) for x in conn.execute('SELECT * FROM hospedes WHERE hotel_id=? ORDER BY nome',(g.hotel_id,)).fetchall()]),200
    finally: conn.close()

@app.route('/api/hospedes',methods=['POST'])
@token_required
def criar_hospede(current_user,role):
    data=request.get_json(silent=True) or {}; nome=str(data.get('nome') or '').strip()[:180]
    if not nome: return jsonify({'erro':'Nome do hóspede é obrigatório.'}),400
    conn=get_db()
    try:
        cur=conn.cursor(); cur.execute('INSERT INTO hospedes (nome,documento,telefone,email,observacoes,hotel_id) VALUES (?,?,?,?,?,?)',
            (nome,str(data.get('documento') or '').strip()[:40] or None,str(data.get('telefone') or '').strip()[:30] or None,str(data.get('email') or '').strip()[:160] or None,str(data.get('observacoes') or '').strip()[:1000] or None,g.hotel_id))
        hid=cur.lastrowid; conn.commit(); return jsonify({'mensagem':'Hóspede cadastrado.','id':hid}),201
    finally: conn.close()

@app.route('/api/hospedes/<int:hid>',methods=['PUT'])
@token_required
def editar_hospede(current_user,role,hid):
    data=request.get_json(silent=True) or {}; conn=get_db()
    try:
        h=conn.execute('SELECT * FROM hospedes WHERE id=? AND hotel_id=?',(hid,g.hotel_id)).fetchone()
        if not h: return jsonify({'erro':'Hóspede não encontrado.'}),404
        nome=str(data.get('nome',h['nome']) or '').strip()[:180]
        if not nome: return jsonify({'erro':'Nome é obrigatório.'}),400
        conn.execute('UPDATE hospedes SET nome=?,documento=?,telefone=?,email=?,observacoes=? WHERE id=? AND hotel_id=?',
            (nome,str(data.get('documento',h['documento']) or '').strip()[:40] or None,str(data.get('telefone',h['telefone']) or '').strip()[:30] or None,str(data.get('email',h['email']) or '').strip()[:160] or None,str(data.get('observacoes',h['observacoes']) or '').strip()[:1000] or None,hid,g.hotel_id))
        conn.commit(); return jsonify({'mensagem':'Hóspede atualizado.'}),200
    finally: conn.close()

@app.route('/api/faixas_etarias',methods=['GET'])
@token_required
def listar_faixas(current_user,role):
    conn=get_db()
    try: return jsonify([dict(x) for x in conn.execute('SELECT * FROM faixas_etarias WHERE hotel_id=? ORDER BY idade_min,nome',(g.hotel_id,)).fetchall()]),200
    finally: conn.close()

@app.route('/api/faixas_etarias',methods=['POST'])
@token_required
def criar_faixa(current_user,role):
    data=request.get_json(silent=True) or {}
    try: minimo=int(data.get('idade_min',0)); maximo=int(data.get('idade_max',120)); adicional=float(data.get('valor_adicional',0))
    except (TypeError,ValueError): return jsonify({'erro':'Valores da faixa inválidos.'}),400
    nome=str(data.get('nome') or '').strip()[:100]
    if not nome or minimo<0 or maximo<minimo or adicional<0: return jsonify({'erro':'Revise os dados da categoria.'}),400
    conn=get_db()
    try:
        conn.execute('INSERT INTO faixas_etarias (nome,idade_min,idade_max,valor_adicional,hotel_id) VALUES (?,?,?,?,?)',(nome,minimo,maximo,adicional,g.hotel_id)); conn.commit()
        return jsonify({'mensagem':'Categoria salva.'}),201
    finally: conn.close()

@app.route('/api/faixas_etarias/<int:fid>',methods=['PUT'])
@token_required
def editar_faixa(current_user,role,fid):
    data=request.get_json(silent=True) or {}; conn=get_db()
    try:
        f=conn.execute('SELECT * FROM faixas_etarias WHERE id=? AND hotel_id=?',(fid,g.hotel_id)).fetchone()
        if not f: return jsonify({'erro':'Categoria não encontrada.'}),404
        try: minimo=int(data.get('idade_min',f['idade_min'])); maximo=int(data.get('idade_max',f['idade_max'])); adicional=float(data.get('valor_adicional',f['valor_adicional']))
        except (TypeError,ValueError): return jsonify({'erro':'Valores inválidos.'}),400
        nome=str(data.get('nome',f['nome']) or '').strip()[:100]
        if not nome or minimo<0 or maximo<minimo or adicional<0: return jsonify({'erro':'Revise os dados da categoria.'}),400
        conn.execute('UPDATE faixas_etarias SET nome=?,idade_min=?,idade_max=?,valor_adicional=? WHERE id=? AND hotel_id=?',(nome,minimo,maximo,adicional,fid,g.hotel_id)); conn.commit()
        return jsonify({'mensagem':'Categoria atualizada.'}),200
    finally: conn.close()

@app.route('/api/faixas_etarias/<int:fid>',methods=['DELETE'])
@token_required
def deletar_faixa(current_user,role,fid):
    conn=get_db()
    try:
        if not conn.execute('SELECT id FROM faixas_etarias WHERE id=? AND hotel_id=?',(fid,g.hotel_id)).fetchone(): return jsonify({'erro':'Categoria não encontrada.'}),404
        conn.execute('DELETE FROM faixas_etarias WHERE id=? AND hotel_id=?',(fid,g.hotel_id)); conn.commit(); return jsonify({'mensagem':'Categoria removida.'}),200
    finally: conn.close()

@app.route('/api/reservas',methods=['GET'])
@token_required
def listar_reservas(current_user,role):
    conn=get_db()
    try:
        sincronizar_status_quartos(conn,g.hotel_id); conn.commit()
        rows=conn.execute('SELECT r.*,h.nome AS hospede_nome,q.id AS quarto_id FROM reservas r LEFT JOIN hospedes h ON h.id=r.hospede_id AND h.hotel_id=r.hotel_id LEFT JOIN quartos q ON q.numero=r.quarto_numero AND q.hotel_id=r.hotel_id WHERE r.hotel_id=? ORDER BY r.id DESC',(g.hotel_id,)).fetchall()
        return jsonify([dict(x) for x in rows]),200
    finally: conn.close()

@app.route('/api/reservas',methods=['POST'])
@token_required
def criar_reserva(current_user,role):
    data=request.get_json(silent=True) or {}
    try:
        hospede_id=int(data.get('hospede_id')); quarto_numero=str(data.get('quarto_numero') or '').strip(); check_in=str(data.get('check_in') or ''); check_out=str(data.get('check_out') or '')
        data_in=datetime.date.fromisoformat(check_in); data_out=datetime.date.fromisoformat(check_out)
    except (TypeError,ValueError): return jsonify({'erro':'Informe hóspede, quarto e datas válidas.'}),400
    if data_out<=data_in: return jsonify({'erro':'O check-out deve ser posterior ao check-in.'}),400
    diarias=(data_out-data_in).days
    conn=get_db()
    try:
        if not conn.execute('SELECT id FROM hospedes WHERE id=? AND hotel_id=?',(hospede_id,g.hotel_id)).fetchone(): return jsonify({'erro':'Hóspede não pertence ao hotel.'}),403
        q=conn.execute('SELECT * FROM quartos WHERE numero=? AND hotel_id=?',(quarto_numero,g.hotel_id)).fetchone()
        if not q: return jsonify({'erro':'Quarto não encontrado.'}),404
        if reserva_conflito(conn,g.hotel_id,quarto_numero,check_in,check_out): return jsonify({'erro':'Já existe uma reserva para este quarto no período informado.'}),409
        extra,det=composicao_reserva(conn,g.hotel_id,data.get('composicao',[]))
        total=round((float(q['preco_diaria'])+extra)*diarias,2)
        cur=conn.cursor()
        cur.execute('INSERT INTO reservas (hospede_id,quarto_numero,check_in,check_out,detalhes_pessoas,diarias,status,valor_total,status_pagamento,hotel_id,criada_por) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                    (hospede_id,quarto_numero,check_in,check_out,det,diarias,'CONFIRMADA',total,'PENDENTE',g.hotel_id,g.current_user_id))
        rid=cur.lastrowid; sincronizar_status_quartos(conn,g.hotel_id); conn.commit()
        return jsonify({'mensagem':'Reserva criada. O pagamento permanece pendente.','valor_total':total,'id':rid}),201
    finally: conn.close()

@app.route('/api/reservas/<int:rid>',methods=['PUT'])
@token_required
def editar_reserva(current_user,role,rid):
    data=request.get_json(silent=True) or {}; conn=get_db()
    try:
        r=conn.execute('SELECT * FROM reservas WHERE id=? AND hotel_id=?',(rid,g.hotel_id)).fetchone()
        if not r: return jsonify({'erro':'Reserva não encontrada.'}),404
        if r['status']=='CANCELADA': return jsonify({'erro':'Reserva cancelada não pode ser editada.'}),409
        try: hospede_id=int(data.get('hospede_id',r['hospede_id'])); quarto_numero=str(data.get('quarto_numero',r['quarto_numero']) or '').strip(); check_in=str(data.get('check_in',r['check_in'])); check_out=str(data.get('check_out',r['check_out']))
        except (TypeError,ValueError): return jsonify({'erro':'Dados inválidos.'}),400
        try: diarias=(datetime.date.fromisoformat(check_out)-datetime.date.fromisoformat(check_in)).days
        except ValueError: return jsonify({'erro':'Datas inválidas.'}),400
        if diarias<1: return jsonify({'erro':'O check-out deve ser posterior ao check-in.'}),400
        if not conn.execute('SELECT id FROM hospedes WHERE id=? AND hotel_id=?',(hospede_id,g.hotel_id)).fetchone(): return jsonify({'erro':'Hóspede inválido.'}),403
        q=conn.execute('SELECT * FROM quartos WHERE numero=? AND hotel_id=?',(quarto_numero,g.hotel_id)).fetchone()
        if not q: return jsonify({'erro':'Quarto não encontrado.'}),404
        if reserva_conflito(conn,g.hotel_id,quarto_numero,check_in,check_out,rid): return jsonify({'erro':'Existe outra reserva conflitante para este quarto.'}),409
        extra,det=composicao_reserva(conn,g.hotel_id,data.get('composicao',[]))
        total=round((float(q['preco_diaria'])+extra)*diarias,2)
        conn.execute('UPDATE reservas SET hospede_id=?,quarto_numero=?,check_in=?,check_out=?,detalhes_pessoas=?,diarias=?,valor_total=? WHERE id=? AND hotel_id=?',(hospede_id,quarto_numero,check_in,check_out,det,diarias,total,rid,g.hotel_id))
        if r['financeiro_id']:
            conn.execute("UPDATE fluxo_caixa SET valor=?,descricao=? WHERE id=? AND hotel_id=? AND origem_tipo='RESERVA' AND origem_id=?",(total,f"Reserva do quarto {quarto_numero} - {check_in} a {check_out}",r['financeiro_id'],g.hotel_id,rid))
        sincronizar_status_quartos(conn,g.hotel_id); conn.commit()
        return jsonify({'mensagem':'Reserva atualizada.','valor_total':total}),200
    finally: conn.close()

@app.route('/api/reservas/<int:rid>/pagamento',methods=['PUT'])
@token_required
def marcar_pagamento_reserva(current_user,role,rid):
    data=request.get_json(silent=True) or {}; status=str(data.get('status','PENDENTE')).upper(); forma=str(data.get('forma_pagamento','NÃO INFORMADO')).strip()[:40]
    conn=get_db()
    try:
        r=conn.execute('SELECT * FROM reservas WHERE id=? AND hotel_id=?',(rid,g.hotel_id)).fetchone()
        if not r: return jsonify({'erro':'Reserva não encontrada.'}),404
        if r['status']=='CANCELADA': return jsonify({'erro':'Reserva cancelada não pode ser paga.'}),409
        if status=='PAGO':
            registrar_entrada_reserva(conn,rid,forma)
        elif status in ('PENDENTE','NAO_PAGO'):
            if r['financeiro_id']:
                conn.execute("DELETE FROM fluxo_caixa WHERE id=? AND hotel_id=? AND origem_tipo='RESERVA' AND origem_id=?",(r['financeiro_id'],g.hotel_id,rid))
            conn.execute("UPDATE reservas SET status_pagamento='PENDENTE',financeiro_id=NULL,pago_em=NULL,pago_por=NULL WHERE id=? AND hotel_id=?",(rid,g.hotel_id))
        else: return jsonify({'erro':'Status de pagamento inválido.'}),400
        conn.commit(); atual=conn.execute('SELECT status_pagamento FROM reservas WHERE id=? AND hotel_id=?',(rid,g.hotel_id)).fetchone()['status_pagamento']
        return jsonify({'mensagem':'Pagamento atualizado.','status_pagamento':atual}),200
    finally: conn.close()

@app.route('/api/reservas/<int:rid>/cancelar',methods=['PUT'])
@token_required
def cancelar_reserva(current_user,role,rid):
    conn=get_db()
    try:
        r=conn.execute('SELECT * FROM reservas WHERE id=? AND hotel_id=?',(rid,g.hotel_id)).fetchone()
        if not r: return jsonify({'erro':'Reserva não encontrada.'}),404
        if r['financeiro_id']:
            conn.execute("DELETE FROM fluxo_caixa WHERE id=? AND hotel_id=? AND origem_tipo='RESERVA' AND origem_id=?",(r['financeiro_id'],g.hotel_id,rid))
        conn.execute("UPDATE reservas SET status='CANCELADA',status_pagamento='PENDENTE',financeiro_id=NULL,pago_em=NULL,pago_por=NULL WHERE id=? AND hotel_id=?",(rid,g.hotel_id))
        sincronizar_status_quartos(conn,g.hotel_id); conn.commit(); return jsonify({'mensagem':'Reserva cancelada.'}),200
    finally: conn.close()

@app.route('/api/estoque',methods=['GET','POST'])
@token_required
def gerenciar_estoque(current_user,role):
    conn=get_db()
    try:
        if request.method=='POST':
            data=request.get_json(silent=True) or {}
            item=str(data.get('item') or '').strip()[:120]; categoria=str(data.get('categoria') or 'Geral').strip()[:80]
            try: quantidade=int(data.get('quantidade',0)); preco=float(data.get('preco_unitario',0))
            except (TypeError,ValueError): return jsonify({'erro':'Quantidade ou preço inválido.'}),400
            if not item or quantidade<0 or preco<0: return jsonify({'erro':'Informe dados válidos.'}),400
            cur=conn.cursor(); cur.execute('INSERT INTO estoque (item,categoria,quantidade,preco_unitario,hotel_id) VALUES (?,?,?,?,?)',(item,categoria,quantidade,preco,g.hotel_id)); conn.commit()
            return jsonify({'mensagem':'Item adicionado.','id':cur.lastrowid}),201
        return jsonify([dict(x) for x in conn.execute('SELECT * FROM estoque WHERE hotel_id=? ORDER BY item',(g.hotel_id,)).fetchall()]),200
    finally: conn.close()

@app.route('/api/estoque/<int:item_id>',methods=['PUT'])
@token_required
def editar_estoque(current_user,role,item_id):
    data=request.get_json(silent=True) or {}; conn=get_db()
    try:
        row=conn.execute('SELECT * FROM estoque WHERE id=? AND hotel_id=?',(item_id,g.hotel_id)).fetchone()
        if not row: return jsonify({'erro':'Item não encontrado.'}),404
        try: qtd=int(data.get('quantidade',row['quantidade'])); preco=float(data.get('preco_unitario',row['preco_unitario']))
        except (TypeError,ValueError): return jsonify({'erro':'Valores inválidos.'}),400
        item=str(data.get('item',row['item']) or '').strip()[:120]; cat=str(data.get('categoria',row['categoria']) or '').strip()[:80]
        if not item or qtd<0 or preco<0: return jsonify({'erro':'Revise item, quantidade e preço.'}),400
        conn.execute('UPDATE estoque SET item=?,categoria=?,quantidade=?,preco_unitario=? WHERE id=? AND hotel_id=?',(item,cat,qtd,preco,item_id,g.hotel_id)); conn.commit()
        return jsonify({'mensagem':'Item atualizado.'}),200
    finally: conn.close()

@app.route('/api/estoque/<int:item_id>',methods=['DELETE'])
@token_required
def deletar_estoque(current_user,role,item_id):
    conn=get_db()
    try:
        cur=conn.cursor(); cur.execute('DELETE FROM estoque WHERE id=? AND hotel_id=?',(item_id,g.hotel_id))
        if cur.rowcount==0: return jsonify({'erro':'Item não encontrado.'}),404
        conn.commit(); return jsonify({'mensagem':'Item removido.'}),200
    finally: conn.close()

@app.route('/api/financeiro',methods=['GET','POST'])
@token_required
def gerenciar_financeiro(current_user,role):
    conn=get_db()
    try:
        if request.method=='POST':
            data=request.get_json(silent=True) or {}
            tipo=str(data.get('tipo') or 'ENTRADA').upper(); desc=str(data.get('descricao') or '').strip()[:200]; cat=str(data.get('categoria') or 'Geral').strip()[:80]
            try: valor=float(data.get('valor',0))
            except (TypeError,ValueError): return jsonify({'erro':'Valor inválido.'}),400
            if tipo not in ('ENTRADA','SAIDA') or not desc or valor<0: return jsonify({'erro':'Dados inválidos.'}),400
            cur=conn.cursor(); cur.execute('INSERT INTO fluxo_caixa (tipo,descricao,valor,categoria,data,hotel_id,origem_tipo,criado_por) VALUES (?,?,?,?,?,?,?,?)',(tipo,desc,valor,cat,str(data.get('data') or datetime.date.today().isoformat()),g.hotel_id,None,g.current_user_id)); conn.commit()
            return jsonify({'mensagem':'Lançamento realizado.','id':cur.lastrowid}),201
        return jsonify([dict(x) for x in conn.execute('SELECT * FROM fluxo_caixa WHERE hotel_id=? ORDER BY id DESC',(g.hotel_id,)).fetchall()]),200
    finally: conn.close()

@app.route('/api/financeiro/<int:fid>',methods=['PUT'])
@token_required
def editar_financeiro(current_user,role,fid):
    data=request.get_json(silent=True) or {}; conn=get_db()
    try:
        row=conn.execute('SELECT * FROM fluxo_caixa WHERE id=? AND hotel_id=?',(fid,g.hotel_id)).fetchone()
        if not row: return jsonify({'erro':'Lançamento não encontrado.'}),404
        if row['origem_tipo']: return jsonify({'erro':'Este lançamento é automático e deve ser alterado pela reserva ou pedido de origem.'}),409
        tipo=str(data.get('tipo',row['tipo']) or '').upper(); desc=str(data.get('descricao',row['descricao']) or '').strip()[:200]; cat=str(data.get('categoria',row['categoria']) or '').strip()[:80]
        try: valor=float(data.get('valor',row['valor']))
        except (TypeError,ValueError): return jsonify({'erro':'Valor inválido.'}),400
        if tipo not in ('ENTRADA','SAIDA') or not desc or valor<0: return jsonify({'erro':'Dados inválidos.'}),400
        conn.execute('UPDATE fluxo_caixa SET tipo=?,descricao=?,valor=?,categoria=? WHERE id=? AND hotel_id=?',(tipo,desc,valor,cat,fid,g.hotel_id)); conn.commit()
        return jsonify({'mensagem':'Lançamento atualizado.'}),200
    finally: conn.close()

@app.route('/api/ordens',methods=['GET','POST'])
@token_required
def gerenciar_ordens(current_user,role):
    conn=get_db()
    try:
        if request.method=='POST':
            data=request.get_json(silent=True) or {}
            tipo=str(data.get('tipo') or 'Outros').strip()[:100]; desc=str(data.get('descricao') or '').strip()[:1000]; prioridade=str(data.get('prioridade') or 'NORMAL').upper()
            if prioridade not in ('BAIXA','NORMAL','ALTA','URGENTE'): prioridade='NORMAL'
            try: quarto_id=int(data.get('quarto_id'))
            except (TypeError,ValueError): return jsonify({'erro':'Selecione um quarto válido.'}),400
            q=conn.execute('SELECT * FROM quartos WHERE id=? AND hotel_id=?',(quarto_id,g.hotel_id)).fetchone()
            if not q: return jsonify({'erro':'Quarto não pertence ao hotel.'}),403
            hospede_id=data.get('hospede_id')
            if hospede_id not in (None,''):
                try: hospede_id=int(hospede_id)
                except (TypeError,ValueError): return jsonify({'erro':'Hóspede inválido.'}),400
                if not conn.execute('SELECT id FROM hospedes WHERE id=? AND hotel_id=?',(hospede_id,g.hotel_id)).fetchone(): return jsonify({'erro':'Hóspede não pertence ao hotel.'}),403
            responsavel_id=data.get('responsavel_id')
            if responsavel_id not in (None,''):
                try: responsavel_id=int(responsavel_id)
                except (TypeError,ValueError): return jsonify({'erro':'Responsável inválido.'}),400
                if not conn.execute("SELECT id FROM usuarios WHERE id=? AND hotel_id=? AND ativo=1",(responsavel_id,g.hotel_id)).fetchone(): return jsonify({'erro':'Responsável inválido.'}),400
            if not tipo or not desc: return jsonify({'erro':'Tipo e descrição são obrigatórios.'}),400
            cur=conn.cursor(); now=datetime.datetime.utcnow().isoformat()
            cur.execute('INSERT INTO ordens_servico (quarto,tipo,descricao,status,hotel_id,quarto_id,hospede_id,solicitante_id,responsavel_id,prioridade,aberta_em) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                        (q['numero'],tipo,desc,'PENDENTE',g.hotel_id,quarto_id,hospede_id,g.current_user_id,responsavel_id,prioridade,now))
            oid=cur.lastrowid; conn.commit(); return jsonify({'mensagem':'Ordem de serviço criada.','id':oid}),201
        rows=conn.execute('''
            SELECT o.*,h.nome AS hospede_nome,u.nome AS responsavel_nome,sol.nome AS solicitante_nome
            FROM ordens_servico o
            LEFT JOIN hospedes h ON h.id=o.hospede_id AND h.hotel_id=o.hotel_id
            LEFT JOIN usuarios u ON u.id=o.responsavel_id AND u.hotel_id=o.hotel_id
            LEFT JOIN usuarios sol ON sol.id=o.solicitante_id AND sol.hotel_id=o.hotel_id
            WHERE o.hotel_id=? ORDER BY CASE o.prioridade WHEN 'URGENTE' THEN 1 WHEN 'ALTA' THEN 2 WHEN 'NORMAL' THEN 3 ELSE 4 END,o.id DESC
        ''',(g.hotel_id,)).fetchall()
        return jsonify([dict(x) for x in rows]),200
    finally: conn.close()

@app.route('/api/ordens/<int:oid>/status',methods=['PUT'])
@token_required
def atualizar_ordem(current_user,role,oid):
    data=request.get_json(silent=True) or {}; status=str(data.get('status','CONCLUIDA')).upper()
    if status not in ('PENDENTE','EM_ANDAMENTO','CONCLUIDA','CANCELADA'): return jsonify({'erro':'Status inválido.'}),400
    conn=get_db()
    try:
        if not conn.execute('SELECT id FROM ordens_servico WHERE id=? AND hotel_id=?',(oid,g.hotel_id)).fetchone(): return jsonify({'erro':'Ordem não encontrada.'}),404
        concluida=datetime.datetime.utcnow().isoformat() if status=='CONCLUIDA' else None
        conn.execute('UPDATE ordens_servico SET status=?,concluida_em=? WHERE id=? AND hotel_id=?',(status,concluida,oid,g.hotel_id)); conn.commit()
        return jsonify({'mensagem':'Status da OS atualizado.'}),200
    finally: conn.close()

@app.route('/api/ordens/<int:oid>',methods=['PUT'])
@token_required
def editar_ordem(current_user,role,oid):
    data=request.get_json(silent=True) or {}; conn=get_db()
    try:
        o=conn.execute('SELECT * FROM ordens_servico WHERE id=? AND hotel_id=?',(oid,g.hotel_id)).fetchone()
        if not o: return jsonify({'erro':'Ordem não encontrada.'}),404
        try: quarto_id=int(data.get('quarto_id',o['quarto_id']))
        except (TypeError,ValueError): return jsonify({'erro':'Quarto inválido.'}),400
        q=conn.execute('SELECT * FROM quartos WHERE id=? AND hotel_id=?',(quarto_id,g.hotel_id)).fetchone()
        if not q: return jsonify({'erro':'Quarto inválido.'}),400
        hospede_id=data.get('hospede_id',o['hospede_id'])
        if hospede_id not in (None,'') and not conn.execute('SELECT id FROM hospedes WHERE id=? AND hotel_id=?',(int(hospede_id),g.hotel_id)).fetchone(): return jsonify({'erro':'Hóspede inválido.'}),400
        resp=data.get('responsavel_id',o['responsavel_id'])
        if resp not in (None,'') and not conn.execute('SELECT id FROM usuarios WHERE id=? AND hotel_id=? AND ativo=1',(int(resp),g.hotel_id)).fetchone(): return jsonify({'erro':'Responsável inválido.'}),400
        tipo=str(data.get('tipo',o['tipo']) or '').strip()[:100]; desc=str(data.get('descricao',o['descricao']) or '').strip()[:1000]; prioridade=str(data.get('prioridade',o['prioridade']) or 'NORMAL').upper()
        if prioridade not in ('BAIXA','NORMAL','ALTA','URGENTE') or not tipo or not desc: return jsonify({'erro':'Revise os dados da OS.'}),400
        conn.execute('UPDATE ordens_servico SET quarto=?,quarto_id=?,hospede_id=?,tipo=?,descricao=?,prioridade=?,responsavel_id=? WHERE id=? AND hotel_id=?',
                     (q['numero'],q['id'],int(hospede_id) if hospede_id not in (None,'') else None,tipo,desc,prioridade,int(resp) if resp not in (None,'') else None,oid,g.hotel_id))
        conn.commit(); return jsonify({'mensagem':'Ordem atualizada.'}),200
    finally: conn.close()

@app.route('/api/ordens/<int:oid>',methods=['DELETE'])
@token_required
def deletar_ordem(current_user,role,oid):
    conn=get_db()
    try:
        cur=conn.cursor(); cur.execute('DELETE FROM ordens_servico WHERE id=? AND hotel_id=?',(oid,g.hotel_id))
        if cur.rowcount==0: return jsonify({'erro':'Ordem não encontrada.'}),404
        conn.commit(); return jsonify({'mensagem':'Ordem removida.'}),200
    finally: conn.close()

@app.route('/api/relatorios',methods=['GET'])
@token_required
def relatorios_gerenciais(current_user,role):
    conn=get_db()
    try:
        sincronizar_status_quartos(conn,g.hotel_id); conn.commit()
        total=conn.execute('SELECT COUNT(*) AS t FROM quartos WHERE hotel_id=?',(g.hotel_id,)).fetchone()['t']
        ocup=conn.execute("SELECT COUNT(*) AS t FROM quartos WHERE hotel_id=? AND status='OCUPADO'",(g.hotel_id,)).fetchone()['t']
        receita=conn.execute("SELECT COALESCE(SUM(valor_total),0) AS s FROM reservas WHERE hotel_id=? AND status_pagamento='PAGO' AND status<>'CANCELADA'",(g.hotel_id,)).fetchone()['s'] or 0
        serv=conn.execute("SELECT COALESCE(SUM(valor),0) AS s FROM fluxo_caixa WHERE hotel_id=? AND tipo='ENTRADA' AND origem_tipo='PEDIDO'",(g.hotel_id,)).fetchone()['s'] or 0
        diarias=conn.execute("SELECT COALESCE(SUM(diarias),0) AS s FROM reservas WHERE hotel_id=? AND status<>'CANCELADA' AND status_pagamento='PAGO'",(g.hotel_id,)).fetchone()['s'] or 0
        ocupacao=round((ocup/total)*100,2) if total else 0; adr=round(float(receita)/float(diarias),2) if diarias else 0; revpar=round(adr*(ocupacao/100),2)
        return jsonify({'total_quartos':total,'quartos_ocupados':ocup,'taxa_ocupacao':ocupacao,'receita_total':round(float(receita)+float(serv),2),'receita_hospedagem':round(float(receita),2),'receita_servicos':round(float(serv),2),'adr':adr,'revpar':revpar}),200
    finally: conn.close()

def enforce_user_quota(conn,quantidade_nova=1):
    sub=getattr(g,'subscription',None)
    if not sub: return True,None
    usados=conn.execute('SELECT COUNT(*) AS total FROM usuarios WHERE hotel_id=? AND ativo=1',(g.hotel_id,)).fetchone()['total']
    if usados+quantidade_nova>int(sub['limite_usuarios']):
        return False,f"Seu plano permite {sub['limite_usuarios']} usuário(s) ativos. Limite atingido."
    return True,None

def hotel_admin_only(role):
    return role=='admin' and bool(getattr(g,'hotel_id',None))

@app.route('/api/usuarios',methods=['GET'])
@token_required
def listar_usuarios_hotel(current_user,role):
    if not hotel_admin_only(role): return jsonify({'erro':'Apenas o administrador do hotel pode gerenciar a equipe.'}),403
    conn=get_db()
    try:
        rows=conn.execute('SELECT id,username,nome,role,email,ativo,ultimo_login FROM usuarios WHERE hotel_id=? ORDER BY ativo DESC,nome,username',(g.hotel_id,)).fetchall()
        return jsonify([dict(x,role_label=ROLE_LABELS.get(x['role'],x['role'])) for x in rows]),200
    finally: conn.close()

@app.route('/api/usuarios',methods=['POST'])
@token_required
def criar_usuario_hotel(current_user,role):
    if not hotel_admin_only(role): return jsonify({'erro':'Apenas o administrador do hotel pode adicionar perfis.'}),403
    data=request.get_json(silent=True) or {}
    username=str(data.get('username') or '').strip()[:80]; nome=str(data.get('nome') or username).strip()[:160]
    email=str(data.get('email') or '').strip()[:160] or None; senha=str(data.get('password') or '')
    perfil=str(data.get('role') or 'recepcao').strip()
    if perfil not in ROLE_LABELS or perfil=='platform_admin': return jsonify({'erro':'Perfil inválido.'}),400
    if not username or not senha: return jsonify({'erro':'Usuário e senha são obrigatórios.'}),400
    erro=validate_password(senha)
    if erro: return jsonify({'erro':erro}),400
    conn=get_db()
    try:
        if conn.execute('SELECT id FROM usuarios WHERE username=?',(username,)).fetchone(): return jsonify({'erro':'Este nome de usuário já está em uso.'}),409
        ok,mensagem=enforce_user_quota(conn,1)
        if not ok: return jsonify({'erro':mensagem}),403
        cur=conn.cursor()
        cur.execute('INSERT INTO usuarios (username,nome,password,role,hotel_id,email,ativo) VALUES (?,?,?,?,?,?,1)',
                    (username,nome,generate_password_hash(senha,method='pbkdf2:sha256'),perfil,g.hotel_id,email))
        uid=cur.lastrowid; conn.commit(); return jsonify({'mensagem':'Usuário criado.','id':uid}),201
    finally: conn.close()

@app.route('/api/usuarios/<int:uid>',methods=['PUT'])
@token_required
def editar_usuario_hotel(current_user,role,uid):
    if not hotel_admin_only(role): return jsonify({'erro':'Apenas o administrador do hotel pode editar usuários.'}),403
    data=request.get_json(silent=True) or {}; conn=get_db()
    try:
        u=conn.execute('SELECT * FROM usuarios WHERE id=? AND hotel_id=?',(uid,g.hotel_id)).fetchone()
        if not u: return jsonify({'erro':'Usuário não encontrado.'}),404
        novo_nome=str(data.get('nome',u['nome'] or u['username']) or u['username']).strip()[:160]
        email=str(data.get('email',u['email'] or '') or '').strip()[:160] or None
        perfil=str(data.get('role',u['role']) or u['role'])
        ativo=1 if bool(data.get('ativo',u['ativo'])) else 0
        if perfil not in ROLE_LABELS or perfil=='platform_admin': return jsonify({'erro':'Perfil inválido.'}),400
        if uid==g.current_user_id and not ativo: return jsonify({'erro':'O administrador atual não pode se bloquear por esta tela.'}),409
        campos=['nome=?','email=?','role=?','ativo=?']; params=[novo_nome,email,perfil,ativo]
        senha=data.get('password')
        if senha not in (None,''):
            senha_erro=validate_password(str(senha))
            if senha_erro: return jsonify({'erro':senha_erro}),400
            campos.append('password=?'); params.append(generate_password_hash(str(senha),method='pbkdf2:sha256'))
        params.extend([uid,g.hotel_id])
        conn.execute('UPDATE usuarios SET '+','.join(campos)+' WHERE id=? AND hotel_id=?',tuple(params))
        conn.commit(); return jsonify({'mensagem':'Usuário atualizado.'}),200
    finally: conn.close()

@app.route('/api/usuarios/<int:uid>',methods=['DELETE'])
@token_required
def desativar_usuario_hotel(current_user,role,uid):
    if not hotel_admin_only(role): return jsonify({'erro':'Apenas o administrador do hotel pode bloquear usuários.'}),403
    if uid==g.current_user_id: return jsonify({'erro':'O administrador atual não pode se bloquear.'}),409
    conn=get_db()
    try:
        cur=conn.cursor(); cur.execute('UPDATE usuarios SET ativo=0 WHERE id=? AND hotel_id=?',(uid,g.hotel_id))
        if cur.rowcount==0: return jsonify({'erro':'Usuário não encontrado.'}),404
        conn.commit(); return jsonify({'mensagem':'Usuário bloqueado.'}),200
    finally: conn.close()

@app.route('/api/servicos',methods=['GET','POST'])
@token_required
def listar_servicos(current_user,role):
    conn=get_db()
    try:
        if request.method=='POST':
            if not can(role,'services.manage'): return jsonify({'erro':'Seu perfil não pode cadastrar serviços.'}),403
            data=request.get_json(silent=True) or {}
            nome=str(data.get('nome') or '').strip()[:120]; categoria=str(data.get('categoria') or 'Diversos').strip()[:80]
            unidade=str(data.get('unidade') or 'unidade').strip()[:30]
            try: preco=float(data.get('preco',0))
            except (TypeError,ValueError): return jsonify({'erro':'Preço inválido.'}),400
            if not nome or preco<0: return jsonify({'erro':'Informe nome e preço válidos.'}),400
            if conn.execute('SELECT id FROM servicos WHERE hotel_id=? AND nome=?',(g.hotel_id,nome)).fetchone(): return jsonify({'erro':'Já existe um serviço com esse nome.'}),409
            cur=conn.cursor(); cur.execute('INSERT INTO servicos (hotel_id,nome,categoria,preco,unidade,ativo) VALUES (?,?,?,?,?,1)',(g.hotel_id,nome,categoria,preco,unidade)); conn.commit()
            return jsonify({'mensagem':'Serviço criado.','id':cur.lastrowid}),201
        return jsonify([dict(x) for x in conn.execute('SELECT * FROM servicos WHERE hotel_id=? ORDER BY ativo DESC,categoria,nome',(g.hotel_id,)).fetchall()]),200
    finally: conn.close()

@app.route('/api/servicos/<int:sid>',methods=['PUT'])
@token_required
def editar_servico(current_user,role,sid):
    if not can(role,'services.manage'): return jsonify({'erro':'Seu perfil não pode editar serviços.'}),403
    data=request.get_json(silent=True) or {}; conn=get_db()
    try:
        s=conn.execute('SELECT * FROM servicos WHERE id=? AND hotel_id=?',(sid,g.hotel_id)).fetchone()
        if not s: return jsonify({'erro':'Serviço não encontrado.'}),404
        nome=str(data.get('nome',s['nome']) or '').strip()[:120]; categoria=str(data.get('categoria',s['categoria']) or '').strip()[:80]; unidade=str(data.get('unidade',s['unidade']) or '').strip()[:30]
        try: preco=float(data.get('preco',s['preco']))
        except (TypeError,ValueError): return jsonify({'erro':'Preço inválido.'}),400
        ativo=1 if bool(data.get('ativo',s['ativo'])) else 0
        if not nome or preco<0: return jsonify({'erro':'Revise nome e preço.'}),400
        dup=conn.execute('SELECT id FROM servicos WHERE hotel_id=? AND nome=? AND id<>?',(g.hotel_id,nome,sid)).fetchone()
        if dup: return jsonify({'erro':'Já existe outro serviço com esse nome.'}),409
        conn.execute('UPDATE servicos SET nome=?,categoria=?,preco=?,unidade=?,ativo=? WHERE id=? AND hotel_id=?',(nome,categoria,preco,unidade,ativo,sid,g.hotel_id)); conn.commit()
        return jsonify({'mensagem':'Serviço atualizado.'}),200
    finally: conn.close()

@app.route('/api/servicos/<int:sid>',methods=['DELETE'])
@token_required
def deletar_servico(current_user,role,sid):
    if not can(role,'services.manage'): return jsonify({'erro':'Seu perfil não pode remover serviços.'}),403
    conn=get_db()
    try:
        cur=conn.cursor(); cur.execute('UPDATE servicos SET ativo=0 WHERE id=? AND hotel_id=?',(sid,g.hotel_id))
        if cur.rowcount==0: return jsonify({'erro':'Serviço não encontrado.'}),404
        conn.commit(); return jsonify({'mensagem':'Serviço desativado.'}),200
    finally: conn.close()

def registrar_entrada_pedido(conn,pedido_id,forma_pagamento='NÃO INFORMADO'):
    p=conn.execute('SELECT * FROM pedidos_hospede WHERE id=? AND hotel_id=?',(pedido_id,g.hotel_id)).fetchone()
    if not p: raise ValueError('Pedido não encontrado.')
    if p['financeiro_id']: return p['financeiro_id']
    total=round(float(p['quantidade'] or 0)*float(p['preco_unitario'] or 0),2)
    cur=conn.cursor(); cur.execute('INSERT INTO fluxo_caixa (tipo,descricao,valor,categoria,data,hotel_id,origem_tipo,origem_id,forma_pagamento,criado_por) VALUES (?,?,?,?,?,?,?,?,?,?)',
                                    ('ENTRADA',f"Pedido do hóspede - {p['item']} - quarto {p['quarto_id'] or ''}",total,'Serviços',datetime.date.today().isoformat(),g.hotel_id,'PEDIDO',p['id'],forma_pagamento,g.current_user_id))
    fid=cur.lastrowid
    conn.execute("UPDATE pedidos_hospede SET status_pagamento='PAGO',pago_em=?,pago_por=?,financeiro_id=? WHERE id=? AND hotel_id=?",(datetime.datetime.utcnow().isoformat(),g.current_user_id,fid,pedido_id,g.hotel_id))
    return fid

@app.route('/api/pedidos',methods=['GET','POST'])
@token_required
def listar_pedidos(current_user,role):
    conn=get_db()
    try:
        if request.method=='POST':
            data=request.get_json(silent=True) or {}
            reserva_id=data.get('reserva_id'); quarto_id=data.get('quarto_id'); hospede_id=data.get('hospede_id'); servico_id=data.get('servico_id')
            try:
                quarto_id=int(quarto_id)
            except (TypeError,ValueError): return jsonify({'erro':'Selecione um quarto.'}),400
            q=conn.execute('SELECT * FROM quartos WHERE id=? AND hotel_id=?',(quarto_id,g.hotel_id)).fetchone()
            if not q: return jsonify({'erro':'Quarto não pertence ao hotel.'}),403
            if hospede_id not in (None,''):
                try: hospede_id=int(hospede_id)
                except (TypeError,ValueError): return jsonify({'erro':'Hóspede inválido.'}),400
                if not conn.execute('SELECT id FROM hospedes WHERE id=? AND hotel_id=?',(hospede_id,g.hotel_id)).fetchone(): return jsonify({'erro':'Hóspede inválido.'}),403
            if reserva_id not in (None,''):
                try: reserva_id=int(reserva_id)
                except (TypeError,ValueError): reserva_id=None
                if reserva_id and not conn.execute('SELECT id FROM reservas WHERE id=? AND hotel_id=?',(reserva_id,g.hotel_id)).fetchone(): return jsonify({'erro':'Reserva inválida.'}),400
            service=None
            if servico_id not in (None,''):
                try: servico_id=int(servico_id)
                except (TypeError,ValueError): return jsonify({'erro':'Serviço inválido.'}),400
                service=conn.execute('SELECT * FROM servicos WHERE id=? AND hotel_id=? AND ativo=1',(servico_id,g.hotel_id)).fetchone()
                if not service: return jsonify({'erro':'Serviço não encontrado.'}),404
            item=str(data.get('item') or (service['nome'] if service else '')).strip()[:120]
            descricao=str(data.get('descricao') or '').strip()[:500] or None
            try: quantidade=float(data.get('quantidade',1)); preco=float(data.get('preco_unitario',service['preco'] if service else 0))
            except (TypeError,ValueError): return jsonify({'erro':'Quantidade ou preço inválido.'}),400
            if quantidade<=0 or preco<0 or not item: return jsonify({'erro':'Informe item, quantidade e preço válidos.'}),400
            cur=conn.cursor(); cur.execute('INSERT INTO pedidos_hospede (hotel_id,reserva_id,quarto_id,hospede_id,servico_id,item,descricao,quantidade,preco_unitario,status,status_pagamento,solicitado_em,criado_por) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',
                (g.hotel_id,reserva_id,quarto_id,hospede_id,servico_id,item,descricao,quantidade,preco,'ABERTO','PENDENTE',datetime.datetime.utcnow().isoformat(),g.current_user_id))
            pid=cur.lastrowid; conn.commit(); return jsonify({'mensagem':'Pedido lançado para o quarto.','id':pid,'total':round(quantidade*preco,2)}),201
        rows=conn.execute('''
            SELECT p.*,h.nome AS hospede_nome,q.numero AS quarto_numero,s.nome AS servico_nome
            FROM pedidos_hospede p
            LEFT JOIN hospedes h ON h.id=p.hospede_id AND h.hotel_id=p.hotel_id
            LEFT JOIN quartos q ON q.id=p.quarto_id AND q.hotel_id=p.hotel_id
            LEFT JOIN servicos s ON s.id=p.servico_id AND s.hotel_id=p.hotel_id
            WHERE p.hotel_id=? ORDER BY p.id DESC
        ''',(g.hotel_id,)).fetchall()
        return jsonify([dict(x) for x in rows]),200
    finally: conn.close()

@app.route('/api/pedidos/<int:pid>/status',methods=['PUT'])
@token_required
def atualizar_pedido_status(current_user,role,pid):
    data=request.get_json(silent=True) or {}; status=str(data.get('status','ENTREGUE')).upper()
    if status not in ('ABERTO','EM_PREPARO','ENTREGUE','CANCELADO'): return jsonify({'erro':'Status inválido.'}),400
    conn=get_db()
    try:
        p=conn.execute('SELECT id FROM pedidos_hospede WHERE id=? AND hotel_id=?',(pid,g.hotel_id)).fetchone()
        if not p: return jsonify({'erro':'Pedido não encontrado.'}),404
        conn.execute('UPDATE pedidos_hospede SET status=? WHERE id=? AND hotel_id=?',(status,pid,g.hotel_id)); conn.commit(); return jsonify({'mensagem':'Status do pedido atualizado.'}),200
    finally: conn.close()

@app.route('/api/pedidos/<int:pid>/pagamento',methods=['PUT'])
@token_required
def marcar_pagamento_pedido(current_user,role,pid):
    data=request.get_json(silent=True) or {}; status=str(data.get('status','PENDENTE')).upper(); forma=str(data.get('forma_pagamento','NÃO INFORMADO')).strip()[:40]
    conn=get_db()
    try:
        p=conn.execute('SELECT * FROM pedidos_hospede WHERE id=? AND hotel_id=?',(pid,g.hotel_id)).fetchone()
        if not p: return jsonify({'erro':'Pedido não encontrado.'}),404
        if status=='PAGO':
            registrar_entrada_pedido(conn,pid,forma)
        elif status in ('PENDENTE','NAO_PAGO'):
            if p['financeiro_id']: conn.execute("DELETE FROM fluxo_caixa WHERE id=? AND hotel_id=? AND origem_tipo='PEDIDO' AND origem_id=?",(p['financeiro_id'],g.hotel_id,pid))
            conn.execute("UPDATE pedidos_hospede SET status_pagamento='PENDENTE',financeiro_id=NULL,pago_em=NULL,pago_por=NULL WHERE id=? AND hotel_id=?",(pid,g.hotel_id))
        else: return jsonify({'erro':'Status de pagamento inválido.'}),400
        conn.commit(); return jsonify({'mensagem':'Pagamento do pedido atualizado.'}),200
    finally: conn.close()

# ==========================================
# CHECKOUT ASAAS
# ==========================================
# CHECKOUT ASAAS / ASSINATURA RECORRENTE
# ==========================================
def asaas_base_url():
    ambiente=os.getenv('ASAAS_ENV','sandbox').strip().lower()
    return os.getenv('ASAAS_BASE_URL','').strip().rstrip('/') or ('https://api.asaas.com/v3' if ambiente=='producao' else 'https://api-sandbox.asaas.com/v3')

@app.route('/api/assinatura/checkout', methods=['POST'])
@token_required
def criar_checkout_asaas(current_user, role):
    if not require_admin_role():
        return jsonify({'erro':'Apenas o administrador do hotel pode contratar um plano.'}),403
    api_key=os.getenv('ASAAS_API_KEY','').strip()
    public_url=os.getenv('SAAS_PUBLIC_URL','').strip().rstrip('/')
    if not api_key or not public_url:
        return jsonify({'erro':'Configure ASAAS_API_KEY e SAAS_PUBLIC_URL no ambiente do servidor.'}),503

    data=request.get_json(silent=True) or {}
    try:
        plano_id=int(data.get('plano_id'))
    except (TypeError,ValueError):
        return jsonify({'erro':'Plano inválido.'}),400

    conn=get_db()
    try:
        plano=conn.execute('SELECT * FROM planos WHERE id=? AND ativo=1',(plano_id,)).fetchone()
        if not plano: return jsonify({'erro':'Plano não encontrado.'}),404
        if float(plano['preco_mensal']) <= 0:
            return jsonify({'erro':'Este plano não exige checkout pago.'}),400

        referencia=f'hotel:{g.hotel_id}:plan:{plano_id}:{secrets.token_urlsafe(10)}'
        payload={
            'billingTypes':['PIX','CREDIT_CARD'],
            'chargeTypes':['RECURRENT'],
            'minutesToExpire':1440,
            'externalReference':referencia,
            'callback':{
                'successUrl':public_url+'/assinatura/sucesso',
                'cancelUrl':public_url+'/assinatura/cancelada',
                'expiredUrl':public_url+'/assinatura/expirada'
            },
            'items':[{
                'name':plano['nome'],
                'description':plano['descricao'] or 'Assinatura Hotel Master',
                'quantity':1,
                'value':float(plano['preco_mensal'])
            }],
            'subscription':{
                'cycle':'MONTHLY',
                'nextDueDate':(datetime.date.today()+datetime.timedelta(days=1)).isoformat()
            }
        }

        req=urllib.request.Request(
            asaas_base_url()+'/checkouts',
            data=json.dumps(payload).encode('utf-8'),
            method='POST',
            headers={
                'Content-Type':'application/json',
                'User-Agent':'HotelMasterSaaS/1.0',
                'access_token':api_key
            }
        )
        try:
            with urllib.request.urlopen(req,timeout=15) as response:
                body=json.loads(response.read().decode('utf-8'))
        except Exception:
            return jsonify({'erro':'Não foi possível criar o Checkout Asaas. Verifique ambiente e credenciais.'}),502

        checkout_id=body.get('id')
        checkout_url=body.get('link') or body.get('url')
        if checkout_id and not checkout_url:
            checkout_url='https://asaas.com/checkoutSession/show?id='+urllib.parse.quote(str(checkout_id))

        sub=conn.execute('SELECT id FROM assinaturas WHERE hotel_id=? ORDER BY id DESC LIMIT 1',(g.hotel_id,)).fetchone()
        if sub:
            conn.execute('UPDATE assinaturas SET gateway=?,checkout_externo=?,atualizado_em=? WHERE id=?',
                         ('asaas:'+os.getenv('ASAAS_ENV','sandbox'),str(checkout_id or referencia),datetime.datetime.utcnow().isoformat(),sub['id']))
            conn.commit()

        return jsonify({'mensagem':'Checkout criado. A assinatura só será liberada após confirmação do pagamento por webhook.','checkout_url':checkout_url,'checkout_id':checkout_id,'referencia':referencia}),200
    finally:
        conn.close()

@app.route('/assinatura/<estado>')
def assinatura_retorno(estado):
    textos={'sucesso':'Pagamento enviado/confirmado pelo Checkout. O sistema aguardará a confirmação definitiva do webhook.',
            'cancelada':'O Checkout foi cancelado. Nenhuma assinatura foi ativada por este retorno.',
            'expirada':'O Checkout expirou. Nenhuma assinatura foi ativada por este retorno.'}
    return textos.get(estado,'Retorno de assinatura.')

# ==========================================
# API - INTEGRAÇÕES POR HOTEL
# ==========================================
@app.route('/api/integracoes', methods=['GET'])
@token_required
def api_integracoes(current_user, role):
    conn=get_db()
    try:
        integracao=get_hotel_integracoes(conn,g.hotel_id) or {'hotel_id':g.hotel_id}
        integracao['maps_embed_url']=maps_embed_url(integracao)
        integracao['webhook_asaas_url']=os.getenv('SAAS_PUBLIC_URL','').strip().rstrip('/')+'/webhooks/asaas' if os.getenv('SAAS_PUBLIC_URL','').strip() else request.url_root.rstrip('/')+'/webhooks/asaas'
        return jsonify(integracao),200
    finally:
        conn.close()

@app.route('/api/integracoes', methods=['PUT'])
@token_required
def salvar_integracoes(current_user, role):
    if not require_admin_role():
        return jsonify({'erro':'Apenas o administrador pode alterar as integrações do hotel.'}),403
    data=request.get_json(silent=True) or {}
    try:
        urls={campo:normalizar_url(data.get(campo)) for campo in ('booking_url','airbnb_url','expedia_url','hoteis_url','website_url','maps_url')}
    except ValueError as e:
        return jsonify({'erro':str(e)}),400
    try:
        latitude=float(data['latitude']) if data.get('latitude') not in (None,'') else None
        longitude=float(data['longitude']) if data.get('longitude') not in (None,'') else None
    except (TypeError,ValueError):
        return jsonify({'erro':'Latitude/longitude inválidas.'}),400
    if latitude is not None and not -90 <= latitude <= 90: return jsonify({'erro':'Latitude inválida.'}),400
    if longitude is not None and not -180 <= longitude <= 180: return jsonify({'erro':'Longitude inválida.'}),400
    conn=get_db()
    try:
        now=datetime.datetime.utcnow().isoformat()
        values=(g.hotel_id,urls['booking_url'],urls['airbnb_url'],urls['expedia_url'],urls['hoteis_url'],urls['website_url'],
                str(data.get('maps_place_id') or '').strip()[:300] or None,urls['maps_url'],
                str(data.get('maps_nome') or '').strip()[:200] or None,str(data.get('endereco') or '').strip()[:500] or None,
                latitude,longitude,now)
        existing=conn.execute('SELECT id FROM hotel_integracoes WHERE hotel_id=?',(g.hotel_id,)).fetchone()
        if existing:
            conn.execute('''UPDATE hotel_integracoes SET booking_url=?,airbnb_url=?,expedia_url=?,hoteis_url=?,website_url=?,maps_place_id=?,maps_url=?,maps_nome=?,endereco=?,latitude=?,longitude=?,atualizado_em=? WHERE hotel_id=?''',
                         values[1:]+(g.hotel_id,))
        else:
            conn.execute('''INSERT INTO hotel_integracoes (hotel_id,booking_url,airbnb_url,expedia_url,hoteis_url,website_url,maps_place_id,maps_url,maps_nome,endereco,latitude,longitude,atualizado_em) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)''',values)
        conn.commit()
        return jsonify({'mensagem':'Integrações salvas com sucesso.','integracao':get_hotel_integracoes(conn,g.hotel_id)}),200
    finally:
        conn.close()

@app.route('/api/integracoes/maps/pesquisar', methods=['POST'])
@token_required
def pesquisar_maps(current_user, role):
    api_key=os.getenv('GOOGLE_MAPS_API_KEY','').strip()
    if not api_key:
        return jsonify({'erro':'Configure GOOGLE_MAPS_API_KEY no ambiente do servidor.'}),503
    data=request.get_json(silent=True) or {}
    consulta=str(data.get('q') or '').strip()
    if len(consulta)<3 or len(consulta)>300:
        return jsonify({'erro':'Informe o nome ou endereço do hotel (3 a 300 caracteres).'}),400
    payload=json.dumps({'textQuery':consulta,'pageSize':5}).encode('utf-8')
    req=urllib.request.Request('https://places.googleapis.com/v1/places:searchText',data=payload,method='POST',
        headers={'Content-Type':'application/json','X-Goog-Api-Key':api_key,
                 'X-Goog-FieldMask':'places.id,places.displayName,places.formattedAddress,places.location,places.googleMapsUri'})
    try:
        with urllib.request.urlopen(req,timeout=10) as response:
            raw=json.loads(response.read().decode('utf-8'))
    except Exception:
        return jsonify({'erro':'Não foi possível consultar o Google Maps agora.'}),502
    resultados=[]
    for p in raw.get('places',[]):
        loc=p.get('location') or {}
        resultados.append({'id':p.get('id'),'nome':(p.get('displayName') or {}).get('text'),
                           'endereco':p.get('formattedAddress'),'latitude':loc.get('latitude'),
                           'longitude':loc.get('longitude'),'maps_url':p.get('googleMapsUri')})
    return jsonify({'resultados':resultados}),200

# ==========================================
# WEBHOOK - ASAAS
# ==========================================
@app.route('/webhooks/asaas', methods=['POST'])
def webhook_asaas():
    esperado=os.getenv('ASAAS_WEBHOOK_TOKEN','').strip()
    fornecido=request.headers.get('asaas-access-token','').strip()
    if not esperado or not fornecido or not secrets.compare_digest(esperado,fornecido):
        return jsonify({'erro':'Não autorizado.'}),401
    data=request.get_json(silent=True)
    if not isinstance(data,dict):
        return jsonify({'erro':'JSON inválido.'}),400

    event_id=str(data.get('id') or '').strip()
    if not event_id:
        event_id=hashlib.sha256(request.get_data(cache=False)).hexdigest()
    event_type=str(data.get('event') or data.get('event_type') or '').upper()[:120]
    payload=json.dumps(data,ensure_ascii=False,separators=(',',':'))
    now=datetime.datetime.utcnow().isoformat()

    conn=get_db()
    try:
        existente=conn.execute('SELECT id,status FROM webhook_eventos WHERE provider=? AND event_id=?',('asaas',event_id)).fetchone()
        if existente:
            return jsonify({'ok':True,'duplicado':True}),200

        hotel_id=None
        payment=data.get('payment') if isinstance(data.get('payment'),dict) else {}
        subscription=data.get('subscription') if isinstance(data.get('subscription'),dict) else {}
        external_subscription=payment.get('subscription') or subscription.get('id')
        external_reference=payment.get('externalReference') or data.get('externalReference')

        assinatura=None
        if external_subscription:
            assinatura=conn.execute('SELECT * FROM assinaturas WHERE assinatura_externa=? ORDER BY id DESC LIMIT 1',(str(external_subscription),)).fetchone()
        if not assinatura and external_reference:
            text_ref=str(external_reference)
            if text_ref.startswith('hotel:'):
                try: hotel_id=int(text_ref.split(':')[1])
                except (TypeError,ValueError): hotel_id=None
            if hotel_id:
                assinatura=conn.execute('SELECT * FROM assinaturas WHERE hotel_id=? ORDER BY id DESC LIMIT 1',(hotel_id,)).fetchone()

        if assinatura:
            hotel_id=assinatura['hotel_id']

        conn.execute('INSERT INTO webhook_eventos (provider,event_id,event_type,hotel_id,payload,recebido_em,status) VALUES (?,?,?,?,?,?,?)',
                     ('asaas',event_id,event_type,hotel_id,payload,now,'RECEBIDO'))

        if assinatura:
            if external_subscription:
                conn.execute('UPDATE assinaturas SET assinatura_externa=?,atualizado_em=? WHERE id=?',(str(external_subscription),now,assinatura['id']))

            ativadores={'PAYMENT_CONFIRMED','PAYMENT_RECEIVED','PAYMENT_APPROVED','CHECKOUT_PAID'}
            suspensores={'PAYMENT_OVERDUE','PAYMENT_DELETED','PAYMENT_REFUNDED'}
            canceladores={'SUBSCRIPTION_INACTIVATED','SUBSCRIPTION_DELETED','SUBSCRIPTION_CANCELED'}
            if event_type in ativadores:
                plano=conn.execute('SELECT dias_ciclo FROM planos WHERE id=?',(assinatura['plano_id'],)).fetchone()
                dias=int(plano['dias_ciclo'] if plano else 30)
                fim=datetime.date.today()+datetime.timedelta(days=dias)
                conn.execute('UPDATE assinaturas SET status=?,inicio=?,periodo_fim=?,trial_ate=NULL,atualizado_em=? WHERE id=?',
                             ('ATIVA',datetime.date.today().isoformat(),fim.isoformat(),now,assinatura['id']))
                status_evento='PROCESSADO'
            elif event_type in suspensores:
                conn.execute('UPDATE assinaturas SET status=?,atualizado_em=? WHERE id=?',('SUSPENSA',now,assinatura['id']))
                status_evento='PROCESSADO'
            elif event_type in canceladores:
                conn.execute('UPDATE assinaturas SET status=?,atualizado_em=? WHERE id=?',('CANCELADA',now,assinatura['id']))
                status_evento='PROCESSADO'
            elif event_type=='SUBSCRIPTION_CREATED':
                status_evento='PROCESSADO'
            else:
                status_evento='RECEBIDO'
        else:
            status_evento='SEM_VINCULO'

        conn.execute('UPDATE webhook_eventos SET status=?,processado_em=? WHERE provider=? AND event_id=?',(status_evento,now,'asaas',event_id))
        conn.commit()
        return jsonify({'ok':True,'status':status_evento,'event_id':event_id}),200
    except Exception as e:
        conn.rollback()
        try:
            conn.execute('UPDATE webhook_eventos SET status=?,erro=? WHERE provider=? AND event_id=?',('ERRO',str(e)[:500],'asaas',event_id)); conn.commit()
        except Exception: pass
        return jsonify({'erro':'Evento recebido, mas houve falha no processamento.'}),500
    finally:
        conn.close()

# ==========================================
# API - SAAS / CONTA / PLANOS
# ==========================================
@app.route('/api/me')
@token_required
def api_me(current_user,role):
    conn=get_db()
    try:
        hotel=conn.execute('SELECT id,nome,data_cadastro,local,bloqueado,bloqueio_motivo FROM hoteis WHERE id=?',(g.hotel_id,)).fetchone() if g.hotel_id else None
        return jsonify({'usuario':{'id':g.current_user_id,'username':g.current_user,'nome':g.current_user_name,'role':g.current_role,'role_label':ROLE_LABELS.get(g.current_role,g.current_role),'hotel_id':g.hotel_id},
                        'hotel':dict(hotel) if hotel else None,
                        'assinatura':get_subscription(conn,g.hotel_id) if g.hotel_id else None}),200
    finally: conn.close()

@app.route('/api/platform/hoteis')
@token_required
def platform_hoteis(current_user,role):
    if role!='platform_admin': return jsonify({'erro':'Acesso restrito ao administrador do SaaS.'}),403
    conn=get_db()
    try:
        hotels=conn.execute('SELECT * FROM hoteis ORDER BY nome').fetchall()
        out=[]
        for h in hotels:
            admins=conn.execute("SELECT id,nome,username,email,ativo,last_seen FROM (SELECT id,nome,username,email,ativo,ultimo_login AS last_seen FROM usuarios WHERE hotel_id=? AND role='admin') ORDER BY ativo DESC,nome,username",(h['id'],)).fetchall()
            sub=get_subscription(conn,h['id'])
            out.append({'id':h['id'],'nome':h['nome'],'local':h['local'],'bloqueado':int(h['bloqueado'] or 0),
                        'bloqueio_motivo':h['bloqueio_motivo'],'admins':[dict(a) for a in admins],
                        'assinatura':sub})
        return jsonify(out),200
    finally: conn.close()

@app.route('/api/platform/hoteis/<int:hotel_id>/bloqueio',methods=['PUT'])
@token_required
def platform_bloquear_hotel(current_user,role,hotel_id):
    if role!='platform_admin': return jsonify({'erro':'Acesso restrito ao administrador do SaaS.'}),403
    data=request.get_json(silent=True) or {}; bloquear=bool(data.get('bloqueado',True))
    motivo=str(data.get('motivo') or '').strip()[:300] or ('Pagamento pendente' if bloquear else None)
    conn=get_db()
    try:
        h=conn.execute('SELECT id,nome FROM hoteis WHERE id=?',(hotel_id,)).fetchone()
        if not h: return jsonify({'erro':'Hotel não encontrado.'}),404
        conn.execute('UPDATE hoteis SET bloqueado=?,bloqueado_em=?,bloqueio_motivo=? WHERE id=?',
                     (1 if bloquear else 0,datetime.datetime.utcnow().isoformat() if bloquear else None,motivo if bloquear else None,hotel_id))
        conn.commit()
        return jsonify({'mensagem':'Hotel bloqueado.' if bloquear else 'Hotel liberado.','hotel_id':hotel_id}),200
    finally: conn.close()

@app.route('/api/platform/assinaturas/<int:hotel_id>',methods=['PUT'])
@token_required
def platform_atualizar_assinatura(hotel_id,current_user,role):
    if role!='platform_admin': return jsonify({'erro':'Acesso restrito ao administrador do SaaS.'}),403
    data=request.get_json(silent=True) or {}
    try: plano_id=int(data.get('plano_id')); dias=int(data.get('dias',30))
    except (TypeError,ValueError): return jsonify({'erro':'Plano ou período inválido.'}),400
    status=str(data.get('status','ATIVA')).upper()
    if status not in ('ATIVA','TESTE','SUSPENSA','CANCELADA'): return jsonify({'erro':'Status inválido.'}),400
    if dias<0 or dias>3660: return jsonify({'erro':'Período inválido.'}),400
    conn=get_db()
    try:
        if not conn.execute('SELECT id FROM hoteis WHERE id=?',(hotel_id,)).fetchone(): return jsonify({'erro':'Hotel não encontrado.'}),404
        plano=conn.execute('SELECT id FROM planos WHERE id=? AND ativo=1',(plano_id,)).fetchone()
        if not plano: return jsonify({'erro':'Plano não encontrado.'}),404
        hoje=datetime.date.today(); fim=hoje+datetime.timedelta(days=dias)
        cur=conn.cursor()
        cur.execute('INSERT INTO assinaturas (hotel_id,plano_id,status,inicio,periodo_fim,trial_ate,gateway,atualizado_em) VALUES (?,?,?,?,?,?,?,?)',
                    (hotel_id,plano_id,status,hoje.isoformat(),fim.isoformat() if status!='CANCELADA' else None,fim.isoformat() if status=='TESTE' else None,'plataforma',datetime.datetime.utcnow().isoformat()))
        conn.commit()
        return jsonify({'mensagem':'Assinatura atualizada.','hotel_id':hotel_id}),200
    finally: conn.close()

@app.route('/api/assinatura')
@token_required
def api_assinatura(current_user,role):
    conn=get_db()
    try:
        return jsonify(get_subscription(conn,g.hotel_id) if g.hotel_id else {'ativo':False,'status':'PLATAFORMA'}),200
    finally: conn.close()

@app.route('/api/assinatura/limites')
@token_required
def api_assinatura_limites(current_user,role):
    if not g.hotel_id: return jsonify({'plano':None,'quartos':{'usados':0,'limite':None},'usuarios':{'usados':0,'limite':None}}),200
    conn=get_db()
    try:
        sub=get_subscription(conn,g.hotel_id)
        q=conn.execute('SELECT COUNT(*) total FROM quartos WHERE hotel_id=?',(g.hotel_id,)).fetchone()['total']
        u=conn.execute('SELECT COUNT(*) total FROM usuarios WHERE hotel_id=? AND ativo=1',(g.hotel_id,)).fetchone()['total']
        return jsonify({'plano':sub,'quartos':{'usados':q,'limite':sub['limite_quartos'] if sub else 0},'usuarios':{'usados':u,'limite':sub['limite_usuarios'] if sub else 0}}),200
    finally: conn.close()

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
    <h2 class="mb-4 text-center">Cadastro de Novo Hotel</h2>
    
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
    <h3 class="text-center mb-3">Hotel Master</h3>
    
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
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="csrf-token" content="{{ csrf_token }}">
<title>Hotel Master | Gestão hoteleira</title>
<style>
:root{
  --primary:#1f4f8f;--primary-dark:#173b6a;--bg:#f4f6f9;--surface:#fff;--text:#1f2937;
  --muted:#6b7280;--border:#e5e7eb;--success:#157347;--warning:#9a6700;--danger:#b42318;
  --sidebar:#172033;--sidebar-2:#202b40;--sidebar-text:#c7cfdb;
}
*{box-sizing:border-box}
html,body{margin:0;padding:0;font-family:Inter,Segoe UI,Arial,sans-serif;color:var(--text);background:var(--bg)}
body{min-height:100vh}
button,input,select,textarea{font:inherit}
button{cursor:pointer}
.app-shell{display:flex;min-height:100vh}
.sidebar{width:258px;background:var(--sidebar);color:#fff;display:flex;flex-direction:column;min-height:100vh}
.brand{padding:24px 20px 18px;border-bottom:1px solid rgba(255,255,255,.08)}
.brand-title{font-size:19px;font-weight:750;letter-spacing:.2px}
.brand-subtitle{display:block;margin-top:3px;font-size:12px;color:#97a4b7}
.user-panel{padding:16px 18px;border-bottom:1px solid rgba(255,255,255,.08)}
.user-name{font-size:14px;font-weight:650}
.user-role{font-size:11px;color:#97a4b7;margin-top:4px}
.hotel-name{font-size:12px;color:#c7cfdb;margin-top:8px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.nav-area{padding:14px 10px;overflow:auto;flex:1}
.nav-group-title{font-size:10px;text-transform:uppercase;letter-spacing:1.1px;color:#8491a5;padding:0 9px 8px}
.nav-btn{display:flex;align-items:center;width:100%;gap:10px;padding:10px 11px;margin-bottom:3px;background:transparent;border:1px solid transparent;border-radius:8px;color:var(--sidebar-text);text-align:left}
.nav-btn:hover{background:var(--sidebar-2);color:#fff}
.nav-btn.active{background:#284265;border-color:#365a88;color:#fff;font-weight:650}
.nav-code{width:26px;height:26px;border-radius:6px;background:#263651;display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:750}
.nav-btn.active .nav-code{background:#3b6ba4}
.sidebar-footer{padding:14px 12px;border-top:1px solid rgba(255,255,255,.08);display:grid;gap:8px}
.btn-outline-light,.btn-logout{width:100%;padding:10px 12px;border-radius:8px;border:1px solid #39455b;background:transparent;color:#d5dbe3}
.btn-outline-light:hover{background:#263149}
.btn-logout{color:#f5b4b0}
.btn-logout:hover{background:rgba(180,35,24,.12)}
.main{flex:1;min-width:0;display:flex;flex-direction:column}
.topbar{position:sticky;top:0;z-index:20;background:#fff;border-bottom:1px solid var(--border);min-height:70px;display:flex;align-items:center;justify-content:space-between;padding:0 26px}
.topbar-left{display:flex;align-items:center;gap:12px;min-width:0}
.page-title{font-size:21px;font-weight:730;margin:0}
.page-subtitle{font-size:12px;color:var(--muted);margin-top:3px}
.topbar-actions{display:flex;align-items:center;gap:8px}
.content{padding:24px;max-width:1600px;width:100%;margin:0 auto}
.tab{display:none}.tab.active{display:block}
.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:20px;margin-bottom:18px;box-shadow:0 1px 2px rgba(15,23,42,.03)}
.card-header{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;margin-bottom:16px}
.card-title{font-size:16px;font-weight:730;margin:0}
.card-help{font-size:12px;color:var(--muted);margin:4px 0 0}
.form-grid{display:grid;grid-template-columns:repeat(12,minmax(0,1fr));gap:14px}
.field{grid-column:span 3;display:flex;flex-direction:column;gap:6px}
.field.span-6{grid-column:span 6}.field.span-9{grid-column:span 9}.field.span-12{grid-column:span 12}
.field label{font-size:12px;font-weight:650;color:#374151}
.field input,.field select,.field textarea{width:100%;padding:10px 11px;border:1px solid #ccd3dd;border-radius:8px;background:#fff;color:#111827;outline:none}
.field input:focus,.field select:focus,.field textarea:focus{border-color:#6091c8;box-shadow:0 0 0 3px rgba(31,79,143,.1)}
.field textarea{min-height:88px;resize:vertical}
.form-actions{grid-column:span 12;display:flex;gap:8px;justify-content:flex-end;align-items:center}
.btn{padding:9px 13px;border:1px solid transparent;border-radius:8px;font-size:12px;font-weight:650}
.btn-primary{background:var(--primary);color:#fff}.btn-primary:hover{background:var(--primary-dark)}
.btn-secondary{background:#fff;color:#374151;border-color:#cbd5e1}.btn-secondary:hover{background:#f8fafc}
.btn-success{background:#19724a;color:#fff}.btn-success:hover{background:#145a3b}
.btn-danger{background:#b42318;color:#fff}.btn-danger:hover{background:#941f13}
.btn-warning{background:#a05c00;color:#fff}.btn-warning:hover{background:#854d00}
.btn-link{background:transparent;color:var(--primary);padding:6px 8px;border:0}
.hidden{display:none!important}
.notice{padding:11px 13px;border-radius:9px;margin-bottom:14px;font-size:12px}
.notice.info{background:#edf4ff;color:#244e7c;border:1px solid #c9dcf5}
.notice.success{background:#edf8f1;color:#155a3e;border:1px solid #c6e7d4}
.notice.warning{background:#fff7e6;color:#7a5200;border:1px solid #f2d59b}
.notice.danger{background:#fff0ee;color:#8f2016;border:1px solid #f1c0ba}
.metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px}
.metric{background:#fff;border:1px solid var(--border);border-radius:12px;padding:18px}
.metric-label{font-size:11px;color:var(--muted);font-weight:650;text-transform:uppercase;letter-spacing:.7px}
.metric-value{font-size:24px;font-weight:760;margin-top:8px}
.metric-note{font-size:11px;color:var(--muted);margin-top:4px}
.table-wrap{overflow:auto;border:1px solid var(--border);border-radius:10px}
table{width:100%;border-collapse:collapse;background:#fff;min-width:780px}
th,td{padding:11px 12px;border-bottom:1px solid #edf0f3;text-align:left;font-size:12px;vertical-align:middle}
th{background:#f8fafc;color:#475569;font-size:11px;text-transform:uppercase;letter-spacing:.35px;white-space:nowrap}
tr:last-child td{border-bottom:0}
.row-actions{display:flex;gap:5px;flex-wrap:wrap}
.badge{display:inline-flex;align-items:center;padding:5px 8px;border-radius:999px;font-size:10px;font-weight:700;letter-spacing:.2px}
.badge-ok{background:#e8f5ed;color:#16643f}.badge-pending{background:#fff7e2;color:#815800}.badge-danger{background:#fdecea;color:#9f2419}.badge-neutral{background:#eef2f6;color:#52606d}.badge-blue{background:#eaf2fc;color:#22528b}
.toolbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.small{font-size:11px;color:var(--muted)}
.empty{padding:30px;text-align:center;color:var(--muted);font-size:12px}
.kv{display:grid;grid-template-columns:190px 1fr;gap:8px;font-size:12px}
.kv div:nth-child(odd){color:var(--muted)}
.inline-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}
.platform-status{padding:4px 8px;border-radius:999px;font-size:10px;font-weight:700}
.platform-open{background:#e8f5ed;color:#16643f}.platform-blocked{background:#fdecea;color:#9f2419}
.toast-host{position:fixed;right:20px;bottom:20px;z-index:9999;display:grid;gap:8px;max-width:380px}
.toast{background:#111827;color:#fff;padding:12px 14px;border-radius:9px;box-shadow:0 10px 30px rgba(0,0,0,.18);font-size:12px}
.toast.success{background:#14532d}.toast.error{background:#991b1b}
.modal-backdrop{position:fixed;inset:0;background:rgba(15,23,42,.55);z-index:200;display:none;align-items:center;justify-content:center;padding:20px}
.modal-backdrop.open{display:flex}
.modal{width:min(760px,100%);max-height:90vh;overflow:auto;background:#fff;border-radius:14px;border:1px solid var(--border);box-shadow:0 30px 80px rgba(0,0,0,.25)}
.modal-header{display:flex;justify-content:space-between;align-items:center;padding:18px 20px;border-bottom:1px solid var(--border)}
.modal-body{padding:20px}
.modal-footer{padding:16px 20px;border-top:1px solid var(--border);display:flex;justify-content:flex-end;gap:8px}
@media(max-width:1100px){.sidebar{width:220px}.metrics{grid-template-columns:repeat(2,minmax(0,1fr))}.field{grid-column:span 6}}
@media(max-width:760px){.app-shell{display:block}.sidebar{width:100%;min-height:auto}.nav-area{max-height:240px}.main{min-height:70vh}.topbar{padding:0 16px}.content{padding:14px}.field,.field.span-6,.field.span-9{grid-column:span 12}.metrics{grid-template-columns:1fr}.topbar-left{min-width:0}.page-title{font-size:17px}.topbar-actions .btn-secondary{display:none}}
</style>
</head>
<body>
<div class="app-shell">
  <aside class="sidebar">
    <div class="brand">
      <div class="brand-title">Hotel Master</div>
      <span class="brand-subtitle">Gestão hoteleira profissional</span>
    </div>
    <div class="user-panel">
      <div class="user-name" id="user-name">Usuário</div>
      <div class="user-role" id="user-role">Perfil</div>
      <div class="hotel-name" id="hotel-name">Hotel</div>
    </div>
    <div class="nav-area">
      <div class="nav-group-title">Navegação</div>
      <div id="nav"></div>
    </div>
    <div class="sidebar-footer">
      <button type="button" class="btn-outline-light" id="btn-back-side">Voltar</button>
      <a href="/logout" class="btn-logout" style="display:block;text-align:center;text-decoration:none;padding:10px 12px;border-radius:8px;">Sair</a>
    </div>
  </aside>

  <main class="main">
    <header class="topbar">
      <div class="topbar-left">
        <div>
          <h1 class="page-title" id="page-title">Painel</h1>
          <div class="page-subtitle" id="page-subtitle">Gestão operacional</div>
        </div>
      </div>
      <div class="topbar-actions">
        <button type="button" class="btn btn-secondary" id="btn-back-top">Voltar</button>
      </div>
    </header>

    <section class="content">
      <div id="tab-painel" class="tab active"></div>

      <div id="tab-quartos" class="tab">
        <div class="card">
          <div class="card-header"><div><h2 class="card-title" id="quarto-form-title">Novo quarto</h2><p class="card-help">Cadastre, edite e controle a disponibilidade dos quartos.</p></div></div>
          <form id="form-quarto" class="form-grid">
            <input type="hidden" id="q-edit-id">
            <div class="field"><label>Número</label><input id="q-numero" required maxlength="30"></div>
            <div class="field"><label>Tipo</label><input id="q-tipo" required maxlength="80" placeholder="Standard, Luxo, Suíte"></div>
            <div class="field"><label>Diária (R$)</label><input id="q-preco" type="number" min="0.01" step="0.01" required></div>
            <div class="field"><label>Status</label><select id="q-status"><option value="DISPONIVEL">Disponível</option><option value="RESERVADO">Reservado</option><option value="OCUPADO">Ocupado</option><option value="MANUTENCAO">Manutenção</option></select></div>
            <div class="form-actions"><button class="btn btn-secondary hidden" type="button" id="q-cancel">Cancelar edição</button><button class="btn btn-primary" type="submit" id="q-submit">Cadastrar quarto</button></div>
          </form>
        </div>
        <div class="card">
          <div class="card-header"><div><h2 class="card-title">Geração em lote</h2><p class="card-help">Crie vários quartos mantendo a regra de numeração por andar já existente.</p></div></div>
          <form id="form-lote" class="form-grid">
            <div class="field"><label>Quantidade</label><input id="lote-qtd" type="number" min="1" max="500" value="10" required></div>
            <div class="field"><label>Tipo padrão</label><input id="lote-tipo" value="Standard" maxlength="80" required></div>
            <div class="field"><label>Diária base (R$)</label><input id="lote-preco" type="number" min="0.01" step="0.01" required></div>
            <div class="field"><label>Primeiro número</label><input id="lote-inicial" type="number" min="1" value="101" required></div>
            <div class="field"><label>Quartos por andar</label><input id="lote-por-andar" type="number" min="0" max="99" value="10"></div>
            <div class="field span-6"><label>Prévia</label><div id="lote-previa" class="notice info" style="margin:0;">Informe os dados para visualizar a sequência.</div></div>
            <div class="form-actions"><button class="btn btn-primary" type="submit">Gerar quartos</button></div>
          </form>
        </div>
        <div class="card">
          <div class="card-header"><h2 class="card-title">Quartos cadastrados <span class="small" id="contagem-quartos"></span></h2></div>
          <div class="table-wrap"><table><thead><tr><th>Número</th><th>Tipo</th><th>Diária</th><th>Status</th><th>Ações</th></tr></thead><tbody id="tabela-quartos"></tbody></table></div>
        </div>
      </div>

      <div id="tab-hospedes" class="tab">
        <div class="card">
          <div class="card-header"><div><h2 class="card-title" id="hospede-form-title">Novo hóspede</h2><p class="card-help">Mantenha os dados do cliente atualizados para reservas e pedidos.</p></div></div>
          <form id="form-hospede" class="form-grid">
            <input type="hidden" id="h-edit-id">
            <div class="field span-6"><label>Nome completo</label><input id="h-nome" required maxlength="180"></div>
            <div class="field"><label>Documento</label><input id="h-doc" maxlength="40"></div>
            <div class="field"><label>Telefone</label><input id="h-tel" maxlength="30"></div>
            <div class="field"><label>E-mail</label><input id="h-email" type="email" maxlength="160"></div>
            <div class="field span-9"><label>Observações</label><textarea id="h-obs" maxlength="1000"></textarea></div>
            <div class="form-actions"><button class="btn btn-secondary hidden" type="button" id="h-cancel">Cancelar edição</button><button class="btn btn-primary" type="submit" id="h-submit">Salvar hóspede</button></div>
          </form>
        </div>
        <div class="card">
          <div class="card-header"><h2 class="card-title">Hóspedes</h2></div>
          <div class="table-wrap"><table><thead><tr><th>Nome</th><th>Documento</th><th>Telefone</th><th>E-mail</th><th>Ações</th></tr></thead><tbody id="tabela-hospedes"></tbody></table></div>
        </div>
      </div>

      <div id="tab-categorias" class="tab">
        <div class="card">
          <div class="card-header"><div><h2 class="card-title" id="cat-form-title">Nova categoria de pessoa</h2><p class="card-help">Use a categoria para controlar pessoas e adicionais na diária.</p></div></div>
          <form id="form-cat" class="form-grid">
            <input type="hidden" id="cat-edit-id">
            <div class="field span-6"><label>Nome</label><input id="cat-nome" required maxlength="100"></div>
            <div class="field"><label>Idade mínima</label><input id="cat-min" type="number" min="0" required></div>
            <div class="field"><label>Idade máxima</label><input id="cat-max" type="number" min="0" required></div>
            <div class="field"><label>Adicional por diária (R$)</label><input id="cat-adicional" type="number" min="0" step="0.01" value="0"></div>
            <div class="form-actions"><button class="btn btn-secondary hidden" type="button" id="cat-cancel">Cancelar edição</button><button class="btn btn-primary" type="submit" id="cat-submit">Salvar categoria</button></div>
          </form>
        </div>
        <div class="card"><div class="table-wrap"><table><thead><tr><th>Nome</th><th>Idade</th><th>Adicional</th><th>Ações</th></tr></thead><tbody id="tabela-categorias"></tbody></table></div></div>
      </div>

      <div id="tab-reservas" class="tab">
        <div class="card">
          <div class="card-header"><div><h2 class="card-title" id="reserva-form-title">Nova reserva</h2><p class="card-help">O sistema impede conflito de datas e registra pagamento separadamente da receita.</p></div></div>
          <form id="form-reserva" class="form-grid">
            <input type="hidden" id="r-edit-id">
            <div class="field span-6"><label>Hóspede</label><select id="r-hospede-id" required></select></div>
            <div class="field"><label>Quarto</label><select id="r-quarto-num" required></select></div>
            <div class="field"><label>Check-in</label><input id="r-checkin" type="date" required></div>
            <div class="field"><label>Check-out</label><input id="r-checkout" type="date" required></div>
            <div class="field span-12"><label>Composição de pessoas</label><div id="container-faixas-reserva" class="inline-grid"></div></div>
            <div class="form-actions"><button class="btn btn-secondary hidden" type="button" id="r-cancel">Cancelar edição</button><button class="btn btn-primary" type="submit" id="r-submit">Criar reserva</button></div>
          </form>
        </div>
        <div class="card">
          <div class="card-header"><div><h2 class="card-title">Reservas</h2><p class="card-help">Use "Pagou" somente quando a entrada tiver sido efetivamente recebida.</p></div></div>
          <div class="table-wrap"><table><thead><tr><th>ID</th><th>Hóspede</th><th>Quarto</th><th>Período</th><th>Diárias</th><th>Total</th><th>Pagamento</th><th>Ações</th></tr></thead><tbody id="tabela-reservas"></tbody></table></div>
        </div>
      </div>

      <div id="tab-servicos" class="tab">
        <div class="card">
          <div class="card-header"><div><h2 class="card-title" id="servico-form-title">Novo serviço</h2><p class="card-help">A lista já começa com serviços essenciais e pode ser personalizada pelo hotel.</p></div></div>
          <form id="form-servico" class="form-grid">
            <input type="hidden" id="s-edit-id">
            <div class="field span-6"><label>Serviço</label><input id="s-nome" required maxlength="120" placeholder="Ex.: Toalha extra"></div>
            <div class="field"><label>Categoria</label><input id="s-categoria" maxlength="80" value="Diversos"></div>
            <div class="field"><label>Unidade</label><input id="s-unidade" maxlength="30" value="unidade"></div>
            <div class="field"><label>Preço (R$)</label><input id="s-preco" type="number" min="0" step="0.01" required></div>
            <div class="form-actions"><button class="btn btn-secondary hidden" type="button" id="s-cancel">Cancelar edição</button><button class="btn btn-primary" type="submit" id="s-submit">Salvar serviço</button></div>
          </form>
        </div>
        <div class="card">
          <div class="card-header"><div><h2 class="card-title">Lançar pedido ao hóspede</h2><p class="card-help">Exemplo: o cliente pediu uma toalha extra. O lançamento fica vinculado ao quarto, hóspede e, quando houver, à reserva.</p></div></div>
          <form id="form-pedido" class="form-grid">
            <div class="field span-6"><label>Quarto</label><select id="p-quarto" required></select></div>
            <div class="field span-6"><label>Hóspede</label><select id="p-hospede"></select></div>
            <div class="field span-6"><label>Serviço cadastrado</label><select id="p-servico"><option value="">Selecionar serviço</option></select></div>
            <div class="field span-6"><label>Item personalizado</label><input id="p-item" maxlength="120" placeholder="Ex.: Adaptador de tomada"></div>
            <div class="field"><label>Quantidade</label><input id="p-qtd" type="number" min="0.01" step="0.01" value="1"></div>
            <div class="field"><label>Preço unitário (R$)</label><input id="p-preco" type="number" min="0" step="0.01" value="0"></div>
            <div class="field span-9"><label>Observação</label><input id="p-desc" maxlength="500" placeholder="Detalhes do pedido"></div>
            <div class="form-actions"><button class="btn btn-primary" type="submit">Lançar pedido</button></div>
          </form>
        </div>
        <div class="card">
          <div class="card-header"><h2 class="card-title">Serviços cadastrados</h2></div>
          <div class="table-wrap"><table><thead><tr><th>Serviço</th><th>Categoria</th><th>Preço</th><th>Unidade</th><th>Status</th><th>Ações</th></tr></thead><tbody id="tabela-servicos"></tbody></table></div>
        </div>
        <div class="card">
          <div class="card-header"><h2 class="card-title">Pedidos dos hóspedes</h2></div>
          <div class="table-wrap"><table><thead><tr><th>Data</th><th>Quarto</th><th>Hóspede</th><th>Item</th><th>Qtd.</th><th>Total</th><th>Status</th><th>Pagamento</th><th>Ações</th></tr></thead><tbody id="tabela-pedidos"></tbody></table></div>
        </div>
      </div>

      <div id="tab-ordens" class="tab">
        <div class="card">
          <div class="card-header"><div><h2 class="card-title" id="os-form-title">Nova ordem de serviço</h2><p class="card-help">Associe cada solicitação ao quarto e ao hóspede, e direcione para limpeza ou manutenção.</p></div></div>
          <form id="form-os" class="form-grid">
            <input type="hidden" id="os-edit-id">
            <div class="field"><label>Quarto</label><select id="os-quarto" required></select></div>
            <div class="field"><label>Hóspede</label><select id="os-hospede"></select></div>
            <div class="field"><label>Tipo</label><select id="os-tipo"><option>Limpeza</option><option>Manutenção elétrica</option><option>Manutenção hidráulica</option><option>Governança</option><option>Outros</option></select></div>
            <div class="field"><label>Prioridade</label><select id="os-prioridade"><option value="BAIXA">Baixa</option><option value="NORMAL" selected>Normal</option><option value="ALTA">Alta</option><option value="URGENTE">Urgente</option></select></div>
            <div class="field span-6"><label>Responsável</label><select id="os-responsavel"><option value="">A definir</option></select></div>
            <div class="field span-12"><label>Descrição</label><textarea id="os-desc" required maxlength="1000" placeholder="Descreva o que deve ser feito."></textarea></div>
            <div class="form-actions"><button class="btn btn-secondary hidden" type="button" id="os-cancel">Cancelar edição</button><button class="btn btn-primary" type="submit" id="os-submit">Criar OS</button></div>
          </form>
        </div>
        <div class="card"><div class="table-wrap"><table><thead><tr><th>ID</th><th>Quarto</th><th>Hóspede</th><th>Tipo</th><th>Prioridade</th><th>Responsável</th><th>Status</th><th>Ações</th></tr></thead><tbody id="tabela-os"></tbody></table></div></div>
      </div>

      <div id="tab-equipe" class="tab">
        <div class="card">
          <div class="card-header"><div><h2 class="card-title" id="user-form-title">Novo acesso</h2><p class="card-help">Crie perfis separados para recepção, gerente, limpeza, manutenção e financeiro.</p></div></div>
          <form id="form-user" class="form-grid">
            <input type="hidden" id="u-edit-id">
            <div class="field"><label>Nome</label><input id="u-nome" required maxlength="160"></div>
            <div class="field"><label>Usuário</label><input id="u-username" required maxlength="80"></div>
            <div class="field"><label>Perfil</label><select id="u-role"><option value="recepcao">Recepção</option><option value="gerente">Gerente</option><option value="limpeza">Limpeza</option><option value="manutencao">Manutenção</option><option value="financeiro">Financeiro</option></select></div>
            <div class="field"><label>E-mail</label><input id="u-email" type="email" maxlength="160"></div>
            <div class="field span-6"><label>Senha <span class="small">mínimo de 10 caracteres, maiúscula, minúscula e número</span></label><input id="u-password" type="password" maxlength="160"></div>
            <div class="field"><label>Status</label><select id="u-ativo"><option value="1">Ativo</option><option value="0">Bloqueado</option></select></div>
            <div class="form-actions"><button class="btn btn-secondary hidden" type="button" id="u-cancel">Cancelar edição</button><button class="btn btn-primary" type="submit" id="u-submit">Criar acesso</button></div>
          </form>
        </div>
        <div class="card"><div class="table-wrap"><table><thead><tr><th>Nome</th><th>Usuário</th><th>Perfil</th><th>Último login</th><th>Status</th><th>Ações</th></tr></thead><tbody id="tabela-equipe"></tbody></table></div></div>
      </div>

      <div id="tab-estoque" class="tab">
        <div class="card">
          <div class="card-header"><h2 class="card-title" id="estoque-form-title">Novo item de estoque</h2></div>
          <form id="form-estoque" class="form-grid">
            <input type="hidden" id="e-edit-id">
            <div class="field span-6"><label>Item</label><input id="e-item" required maxlength="120"></div>
            <div class="field"><label>Categoria</label><input id="e-cat" required maxlength="80"></div>
            <div class="field"><label>Quantidade</label><input id="e-qtd" type="number" min="0" step="1" required></div>
            <div class="field"><label>Preço unitário</label><input id="e-preco" type="number" min="0" step="0.01" required></div>
            <div class="form-actions"><button class="btn btn-secondary hidden" type="button" id="e-cancel">Cancelar edição</button><button class="btn btn-primary" type="submit" id="e-submit">Adicionar item</button></div>
          </form>
        </div>
        <div class="card"><div class="table-wrap"><table><thead><tr><th>Item</th><th>Categoria</th><th>Quantidade</th><th>Preço</th><th>Ações</th></tr></thead><tbody id="tabela-estoque"></tbody></table></div></div>
      </div>

      <div id="tab-financeiro" class="tab">
        <div class="card">
          <div class="card-header"><div><h2 class="card-title" id="fin-form-title">Novo lançamento</h2><p class="card-help">Entradas de reservas e pedidos pagos aparecem automaticamente no caixa e não devem ser duplicadas.</p></div></div>
          <form id="form-fin" class="form-grid">
            <input type="hidden" id="f-edit-id">
            <div class="field"><label>Tipo</label><select id="f-tipo"><option value="ENTRADA">Entrada</option><option value="SAIDA">Saída</option></select></div>
            <div class="field span-6"><label>Descrição</label><input id="f-desc" required maxlength="200"></div>
            <div class="field"><label>Valor</label><input id="f-valor" type="number" min="0" step="0.01" required></div>
            <div class="field"><label>Categoria</label><input id="f-cat" value="Geral" maxlength="80" required></div>
            <div class="form-actions"><button class="btn btn-secondary hidden" type="button" id="f-cancel">Cancelar edição</button><button class="btn btn-primary" type="submit" id="f-submit">Lançar</button></div>
          </form>
        </div>
        <div class="card"><div class="table-wrap"><table><thead><tr><th>Data</th><th>Tipo</th><th>Descrição</th><th>Categoria</th><th>Valor</th><th>Origem</th><th>Ações</th></tr></thead><tbody id="tabela-financeiro"></tbody></table></div></div>
      </div>

      <div id="tab-relatorios" class="tab">
        <div class="card"><div class="card-header"><div><h2 class="card-title">Relatórios gerenciais</h2><p class="card-help">Indicadores calculados sobre receitas efetivamente pagas.</p></div><button class="btn btn-secondary" type="button" onclick="carregarRelatorios()">Atualizar</button></div><div class="metrics" id="relatorio-metricas"></div></div>
      </div>

      <div id="tab-integracoes" class="tab">
        <div class="card">
          <div class="card-header"><div><h2 class="card-title">Canais e localização</h2><p class="card-help">Links públicos do hotel, Google Maps e localização.</p></div></div>
          <form id="form-integracoes" class="form-grid">
            <div class="field span-6"><label>Booking.com</label><input id="int-booking" type="url" placeholder="https://www.booking.com/..."></div>
            <div class="field span-6"><label>Airbnb</label><input id="int-airbnb" type="url" placeholder="https://www.airbnb.com/rooms/..."></div>
            <div class="field span-6"><label>Expedia</label><input id="int-expedia" type="url"></div>
            <div class="field span-6"><label>Hoteis.com</label><input id="int-hoteis" type="url"></div>
            <div class="field span-6"><label>Site próprio</label><input id="int-site" type="url"></div>
            <div class="field span-6"><label>Google Maps</label><input id="int-maps-url" type="url"></div>
            <div class="field span-6"><label>Nome no Google Maps</label><input id="int-maps-nome" maxlength="200"></div>
            <div class="field span-6"><label>Place ID</label><input id="int-place-id" maxlength="300"></div>
            <div class="field span-12"><label>Endereço</label><input id="int-endereco" maxlength="500"></div>
            <div class="field"><label>Latitude</label><input id="int-lat" type="number" step="any"></div>
            <div class="field"><label>Longitude</label><input id="int-lng" type="number" step="any"></div>
            <div class="form-actions"><button class="btn btn-secondary" type="button" onclick="pesquisarGoogleMaps()">Pesquisar Maps</button><button class="btn btn-primary" type="submit">Salvar integrações</button></div>
          </form>
          <div id="resultado-maps" style="margin-top:14px;"></div>
          <div id="mapa-hotel" style="margin-top:14px;"></div>
        </div>
        <div class="card">
          <div class="card-header"><div><h2 class="card-title">Assinatura do hotel</h2><p class="card-help">Acesso é liberado pelo webhook do gateway, não pelo retorno do checkout.</p></div></div>
          <div class="form-grid">
            <div class="field span-6"><label>Plano</label><select id="saas-plano"></select></div>
            <div class="field"><label>Status</label><input id="saas-status" readonly></div>
            <div class="field"><label>Período final</label><input id="saas-fim" readonly></div>
            <div class="form-actions"><button class="btn btn-primary" type="button" onclick="contratarPlano()">Abrir checkout recorrente</button></div>
          </div>
        </div>
        <div class="card">
          <div class="card-header"><div><h2 class="card-title">Webhook de cobrança</h2><p class="card-help">Configure no Asaas a URL abaixo e o token de autenticação definido no servidor.</p></div></div>
          <div class="field span-12"><label>URL do webhook</label><input id="int-webhook-url" readonly></div>
        </div>
      </div>

      <div id="tab-whatsapp" class="tab">
        <div class="card"><div class="card-header"><div><h2 class="card-title">Mensagens WhatsApp</h2><p class="card-help">Abre a conversa no WhatsApp com a mensagem preparada.</p></div></div>
          <div class="form-grid">
            <div class="field"><label>Telefone</label><input id="wa-tel" placeholder="5561999999999"></div>
            <div class="field span-6"><label>Modelo</label><select id="wa-template"><option value="Olá! Sua reserva está confirmada.">Confirmação de reserva</option><option value="Olá! Seu check-out está previsto para amanhã.">Lembrete de check-out</option><option value="Olá! Agradecemos pela estadia.">Pós-estadia</option></select></div>
            <div class="field span-12"><label>Mensagem</label><textarea id="wa-msg"></textarea></div>
            <div class="form-actions"><button class="btn btn-success" type="button" onclick="enviarWhatsApp()">Abrir WhatsApp</button></div>
          </div>
        </div>
      </div>

      <div id="tab-plataforma" class="tab">
        <div class="card">
          <div class="card-header"><div><h2 class="card-title">Administração do SaaS</h2><p class="card-help">Visão central dos hotéis, administradores, assinaturas e bloqueios.</p></div><button class="btn btn-secondary" type="button" onclick="carregarPlataforma()">Atualizar</button></div>
          <div id="plataforma-aviso" class="notice info">Carregando clientes.</div>
          <div class="table-wrap"><table><thead><tr><th>Hotel</th><th>Administrador(es)</th><th>Plano</th><th>Validade</th><th>Status</th><th>Controle</th></tr></thead><tbody id="tabela-plataforma"></tbody></table></div>
        </div>
      </div>
    </section>
  </main>
</div>
<div class="toast-host" id="toast-host"></div>
<script>
const CONTEXTO_USUARIO = {{ contexto_usuario|tojson }};
const CSRF_TOKEN = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';
const ORIGINAL_FETCH = window.fetch.bind(window);
window.fetch = function(input, init = {}) {
  const method=(init.method||'GET').toUpperCase();
  if(['POST','PUT','PATCH','DELETE'].includes(method)){
    const headers=new Headers(init.headers||{});
    if(CSRF_TOKEN) headers.set('X-CSRFToken',CSRF_TOKEN);
    init={...init,headers};
  }
  return ORIGINAL_FETCH(input,init);
};

const state={quartos:[],hospedes:[],reservas:[],faixas:[],servicos:[],pedidos:[],ordens:[],usuarios:[],estoque:[],financeiro:[],planos:[],sub:null};
let abaAtual=null;
let historicoAbas=[];
const primeiraAba=CONTEXTO_USUARIO.role==='platform_admin'?'plataforma':'painel';

const menusTenant=[
  ['painel','PD','Painel','reports.view'],
  ['quartos','QT','Quartos','rooms.view'],
  ['hospedes','HP','Hóspedes','guests.view'],
  ['categorias','CP','Categorias de pessoas','categories.view'],
  ['reservas','RS','Reservas','reservations.view'],
  ['servicos','SV','Serviços e pedidos','services.view'],
  ['ordens','OS','Ordens de serviço','orders.view'],
  ['equipe','EQ','Equipe e acessos','team.view'],
  ['estoque','ET','Estoque','stock.view'],
  ['financeiro','FN','Financeiro','finance.view'],
  ['relatorios','RL','Relatórios','reports.view'],
  ['integracoes','IN','Integrações','integrations.view'],
  ['whatsapp','WA','WhatsApp','whatsapp.use']
];
const rolePerms={
  admin:new Set(['*']),
  gerente:new Set(['rooms.view','guests.view','categories.view','reservations.view','services.view','orders.view','team.view','stock.view','finance.view','reports.view','integrations.view','whatsapp.use']),
  recepcao:new Set(['rooms.view','guests.view','reservations.view','services.view','orders.view','whatsapp.use']),
  limpeza:new Set(['rooms.view','services.view','orders.view']),
  manutencao:new Set(['rooms.view','orders.view']),
  financeiro:new Set(['rooms.view','guests.view','reservations.view','finance.view','reports.view'])
};
function pode(p){const s=rolePerms[CONTEXTO_USUARIO.role];return s&& (s.has('*')||s.has(p));}
function menuPermitido(id,p){return CONTEXTO_USUARIO.role==='admin'||pode(p)||id==='painel';}
function toast(msg,type=''){const host=document.getElementById('toast-host');const el=document.createElement('div');el.className='toast '+(type||'');el.textContent=msg;host.appendChild(el);setTimeout(()=>el.remove(),3500);}
function escapar(v){const d=document.createElement('div');d.textContent=v==null?'':String(v);return d.innerHTML;}
function moeda(v){return 'R$ '+Number(v||0).toFixed(2).replace('.',',');}
function dataHora(v){if(!v)return '-';try{return new Date(v).toLocaleString('pt-BR');}catch(e){return v;}}
function badgeStatus(s){
  const x=String(s||'').toUpperCase();
  let cl='badge-neutral';
  if(['PAGO','ATIVA','CONCLUIDA','ENTREGUE','DISPONIVEL','ATIVO'].includes(x))cl='badge-ok';
  else if(['PENDENTE','TESTE','ABERTO','EM_PREPARO','EM_ANDAMENTO','RESERVADO'].includes(x))cl='badge-pending';
  else if(['SUSPENSA','CANCELADA','CANCELADO','BLOQUEADO','MANUTENCAO'].includes(x))cl='badge-danger';
  return '<span class="badge '+cl+'">'+escapar(x)+'</span>';
}
async function jsonFetch(url,opts={}){
  const res=await fetch(url,opts);
  const data=await res.json().catch(()=>({}));
  if(!res.ok){
    if(res.status===401){window.location.href='/login';return null;}
    throw new Error(data.erro||data.mensagem||'Não foi possível concluir a operação.');
  }
  return data;
}
function renderNav(){
  const nav=document.getElementById('nav');nav.innerHTML='';
  const menu=CONTEXTO_USUARIO.role==='platform_admin'?[['plataforma','SA','Administração SaaS','platform']]:menusTenant.filter(x=>menuPermitido(x[0],x[3]));
  menu.forEach(item=>{
    const b=document.createElement('button');b.type='button';b.className='nav-btn';b.dataset.tab=item[0];
    b.innerHTML='<span class="nav-code">'+item[1]+'</span><span>'+escapar(item[2])+'</span>';
    b.addEventListener('click',()=>switchTab(item[0]));
    nav.appendChild(b);
  });
}
function tituloAba(tab){
  if(tab==='plataforma')return 'Administração do SaaS';
  const m=menusTenant.find(x=>x[0]===tab);return m?m[2]:'Painel';
}
function switchTab(tab,registrar=true){
  const target=document.getElementById('tab-'+tab);
  if(!target)return;
  if(CONTEXTO_USUARIO.role!=='platform_admin' && tab!=='painel'){
    const m=menusTenant.find(x=>x[0]===tab);
    if(m&&!menuPermitido(m[0],m[3])){toast('Seu perfil não possui acesso a esta área.','error');return;}
  }
  if(registrar&&abaAtual&&abaAtual!==tab)historicoAbas.push(abaAtual);
  abaAtual=tab;
  document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));
  target.classList.add('active');
  document.querySelectorAll('.nav-btn').forEach(x=>x.classList.toggle('active',x.dataset.tab===tab));
  document.getElementById('page-title').textContent=tituloAba(tab);
  const hotel=CONTEXTO_USUARIO.hotel_nome;
  document.getElementById('page-subtitle').textContent=CONTEXTO_USUARIO.role==='platform_admin'?'Controle de clientes e assinaturas':(hotel||'Gestão operacional');
  document.getElementById('user-name').textContent=CONTEXTO_USUARIO.nome;
  document.getElementById('user-role').textContent=CONTEXTO_USUARIO.role_label;
  document.getElementById('hotel-name').textContent=hotel||'Sem hotel vinculado';
  loadTab(tab).catch(e=>toast(e.message,'error'));
}
function voltar(){
  if(historicoAbas.length){const x=historicoAbas.pop();switchTab(x,false);}
  else if(abaAtual!==primeiraAba){switchTab(primeiraAba,false);}
}
document.getElementById('btn-back-top').onclick=voltar;
document.getElementById('btn-back-side').onclick=voltar;

function popularSelect(elId,rows,placeholder,labelFn,valueFn){
  const el=document.getElementById(elId);if(!el)return;
  const atual=el.value;el.innerHTML='';
  if(placeholder!==null){const o=document.createElement('option');o.value='';o.textContent=placeholder;el.appendChild(o);}
  rows.forEach(r=>{const o=document.createElement('option');o.value=valueFn(r);o.textContent=labelFn(r);el.appendChild(o);});
  if([...el.options].some(x=>x.value===atual))el.value=atual;
}
async function carregarBase(){
  const [q,h]=await Promise.all([jsonFetch('/api/quartos'),jsonFetch('/api/hospedes')]);
  state.quartos=q||[];state.hospedes=h||[];
  popularSelect('r-quarto-num',state.quartos.filter(x=>x.status!=='MANUTENCAO'),null,x=>x.numero+' — '+x.tipo,x=>x.numero);
  popularSelect('p-quarto',state.quartos,null,x=>x.numero+' — '+x.tipo,x=>x.id);
  popularSelect('os-quarto',state.quartos,null,x=>x.numero+' — '+x.tipo,x=>x.id);
  popularSelect('r-hospede-id',state.hospedes,null,x=>x.nome,x=>x.id);
  popularSelect('p-hospede',state.hospedes,'Selecionar hóspede',x=>x.nome,x=>x.id);
  popularSelect('os-hospede',state.hospedes,'Sem hóspede específico',x=>x.nome,x=>x.id);
}
function preencherFaixas(){
  const box=document.getElementById('container-faixas-reserva');box.innerHTML='';
  state.faixas.forEach(f=>{
    const div=document.createElement('div');div.className='field';
    div.innerHTML='<label>'+escapar(f.nome)+' — +'+moeda(f.valor_adicional)+'/dia</label><input class="faixa-input" data-id="'+f.id+'" type="number" min="0" step="1" value="0">';
    box.appendChild(div);
  });
}
async function carregarQuartos(){
  state.quartos=await jsonFetch('/api/quartos')||[];
  const tbody=document.getElementById('tabela-quartos');tbody.innerHTML='';
  state.quartos.forEach(q=>{
    const tr=document.createElement('tr');
    tr.innerHTML='<td><strong>'+escapar(q.numero)+'</strong></td><td>'+escapar(q.tipo)+'</td><td>'+moeda(q.preco_diaria)+'</td><td>'+badgeStatus(q.status)+'</td><td><div class="row-actions"><button class="btn btn-secondary" onclick="editarQuarto('+q.id+')">Editar</button><button class="btn btn-danger" onclick="deletarQuarto('+q.id+')">Excluir</button></div></td>';
    tbody.appendChild(tr);
  });
  document.getElementById('contagem-quartos').textContent='('+state.quartos.length+')';
  atualizarPreviaLote();
}
function calcularLote(qtd,inicial,porAndar){
  const arr=[];
  if(porAndar>0){let andar=Math.floor(inicial/100),pos=inicial%100;for(let i=0;i<qtd;i++){arr.push(String(andar*100+pos));pos++;if(pos>porAndar){andar++;pos=1;}}}
  else{for(let i=0;i<qtd;i++)arr.push(String(inicial+i));}
  return arr;
}
function atualizarPreviaLote(){
  const el=document.getElementById('lote-previa');if(!el)return;
  const qtd=parseInt(document.getElementById('lote-qtd').value||'0',10),ini=parseInt(document.getElementById('lote-inicial').value||'0',10),pa=parseInt(document.getElementById('lote-por-andar').value||'0',10);
  if(!(qtd>=1&&qtd<=500&&ini>=1&&pa>=0&&pa<=99)){el.className='notice danger';el.textContent='Informe uma quantidade e uma numeração válidas.';return;}
  if(pa>0&&(ini%100<1||ini%100>pa)){el.className='notice warning';el.textContent='O primeiro número deve estar dentro da quantidade informada para o andar.';return;}
  const nums=calcularLote(qtd,ini,pa);el.className='notice info';el.textContent='Serão criados '+nums.length+' quartos, do '+nums[0]+' ao '+nums[nums.length-1]+'.';
}
function limparQuartoForm(){document.getElementById('form-quarto').reset();document.getElementById('q-edit-id').value='';document.getElementById('q-status').value='DISPONIVEL';document.getElementById('q-cancel').classList.add('hidden');document.getElementById('q-submit').textContent='Cadastrar quarto';document.getElementById('quarto-form-title').textContent='Novo quarto';}
async function editarQuarto(id){const q=state.quartos.find(x=>x.id===id);if(!q)return;switchTab('quartos');document.getElementById('q-edit-id').value=q.id;document.getElementById('q-numero').value=q.numero;document.getElementById('q-tipo').value=q.tipo;document.getElementById('q-preco').value=q.preco_diaria;document.getElementById('q-status').value=q.status;document.getElementById('q-cancel').classList.remove('hidden');document.getElementById('q-submit').textContent='Salvar alterações';document.getElementById('quarto-form-title').textContent='Editar quarto '+q.numero;}
async function deletarQuarto(id){if(!confirm('Excluir este quarto? O sistema não permitirá excluir quarto com reserva ativa ou futura.'))return;try{await jsonFetch('/api/quartos/'+id,{method:'DELETE'});toast('Quarto excluído.','success');carregarQuartos();}catch(e){toast(e.message,'error');}}
document.getElementById('form-quarto').addEventListener('submit',async e=>{e.preventDefault();const id=document.getElementById('q-edit-id').value;const body={numero:document.getElementById('q-numero').value,tipo:document.getElementById('q-tipo').value,preco_diaria:parseFloat(document.getElementById('q-preco').value),status:document.getElementById('q-status').value};try{await jsonFetch(id?'/api/quartos/'+id:'/api/quartos',{method:id?'PUT':'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});toast(id?'Quarto atualizado.':'Quarto cadastrado.','success');limparQuartoForm();carregarQuartos();}catch(e){toast(e.message,'error');}});
document.getElementById('q-cancel').onclick=limparQuartoForm;
document.getElementById('form-lote').addEventListener('submit',async e=>{e.preventDefault();const qtd=parseInt(document.getElementById('lote-qtd').value,10),ini=parseInt(document.getElementById('lote-inicial').value,10),pa=parseInt(document.getElementById('lote-por-andar').value||'0',10),preco=parseFloat(document.getElementById('lote-preco').value);const nums=calcularLote(qtd,ini,pa);if(!confirm('Criar '+nums.length+' quartos?'))return;try{const data=await jsonFetch('/api/quartos/lote',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({quantidade:qtd,numero_inicial:ini,por_andar:pa,tipo:document.getElementById('lote-tipo').value,preco_diaria:preco})});toast(data.mensagem,'success');carregarQuartos();}catch(e){toast(e.message,'error');}});
['lote-qtd','lote-inicial','lote-por-andar'].forEach(id=>document.getElementById(id).addEventListener('input',atualizarPreviaLote));

async function carregarHospedes(){
  state.hospedes=await jsonFetch('/api/hospedes')||[];
  popularSelect('r-hospede-id',state.hospedes,null,x=>x.nome,x=>x.id);popularSelect('p-hospede',state.hospedes,'Selecionar hóspede',x=>x.nome,x=>x.id);popularSelect('os-hospede',state.hospedes,'Sem hóspede específico',x=>x.nome,x=>x.id);
  const tbody=document.getElementById('tabela-hospedes');tbody.innerHTML='';
  state.hospedes.forEach(h=>{const tr=document.createElement('tr');tr.innerHTML='<td><strong>'+escapar(h.nome)+'</strong></td><td>'+escapar(h.documento||'-')+'</td><td>'+escapar(h.telefone||'-')+'</td><td>'+escapar(h.email||'-')+'</td><td><button class="btn btn-secondary" onclick="editarHospede('+h.id+')">Editar</button></td>';tbody.appendChild(tr);});
}
function limparHospedeForm(){document.getElementById('form-hospede').reset();document.getElementById('h-edit-id').value='';document.getElementById('h-cancel').classList.add('hidden');document.getElementById('h-submit').textContent='Salvar hóspede';document.getElementById('hospede-form-title').textContent='Novo hóspede';}
function editarHospede(id){const h=state.hospedes.find(x=>x.id===id);if(!h)return;switchTab('hospedes');document.getElementById('h-edit-id').value=id;document.getElementById('h-nome').value=h.nome;document.getElementById('h-doc').value=h.documento||'';document.getElementById('h-tel').value=h.telefone||'';document.getElementById('h-email').value=h.email||'';document.getElementById('h-obs').value=h.observacoes||'';document.getElementById('h-cancel').classList.remove('hidden');document.getElementById('h-submit').textContent='Salvar alterações';document.getElementById('hospede-form-title').textContent='Editar hóspede';}
document.getElementById('form-hospede').addEventListener('submit',async e=>{e.preventDefault();const id=document.getElementById('h-edit-id').value;const body={nome:document.getElementById('h-nome').value,documento:document.getElementById('h-doc').value,telefone:document.getElementById('h-tel').value,email:document.getElementById('h-email').value,observacoes:document.getElementById('h-obs').value};try{await jsonFetch(id?'/api/hospedes/'+id:'/api/hospedes',{method:id?'PUT':'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});toast(id?'Hóspede atualizado.':'Hóspede cadastrado.','success');limparHospedeForm();carregarHospedes();}catch(e){toast(e.message,'error');}});
document.getElementById('h-cancel').onclick=limparHospedeForm;

async function carregarCategorias(){state.faixas=await jsonFetch('/api/faixas_etarias')||[];preencherFaixas();const tb=document.getElementById('tabela-categorias');tb.innerHTML='';state.faixas.forEach(f=>{const tr=document.createElement('tr');tr.innerHTML='<td>'+escapar(f.nome)+'</td><td>'+f.idade_min+' a '+f.idade_max+'</td><td>'+moeda(f.valor_adicional)+'</td><td><div class="row-actions"><button class="btn btn-secondary" onclick="editarCategoria('+f.id+')">Editar</button><button class="btn btn-danger" onclick="excluirCategoria('+f.id+')">Excluir</button></div></td>';tb.appendChild(tr);});}
function limparCategoriaForm(){document.getElementById('form-cat').reset();document.getElementById('cat-edit-id').value='';document.getElementById('cat-adicional').value='0';document.getElementById('cat-cancel').classList.add('hidden');document.getElementById('cat-submit').textContent='Salvar categoria';document.getElementById('cat-form-title').textContent='Nova categoria de pessoa';}
function editarCategoria(id){const f=state.faixas.find(x=>x.id===id);if(!f)return;switchTab('categorias');document.getElementById('cat-edit-id').value=id;document.getElementById('cat-nome').value=f.nome;document.getElementById('cat-min').value=f.idade_min;document.getElementById('cat-max').value=f.idade_max;document.getElementById('cat-adicional').value=f.valor_adicional;document.getElementById('cat-cancel').classList.remove('hidden');document.getElementById('cat-submit').textContent='Salvar alterações';document.getElementById('cat-form-title').textContent='Editar categoria';}
async function excluirCategoria(id){if(!confirm('Excluir esta categoria?'))return;try{await jsonFetch('/api/faixas_etarias/'+id,{method:'DELETE'});toast('Categoria removida.','success');carregarCategorias();}catch(e){toast(e.message,'error');}}
document.getElementById('form-cat').addEventListener('submit',async e=>{e.preventDefault();const id=document.getElementById('cat-edit-id').value;const body={nome:document.getElementById('cat-nome').value,idade_min:parseInt(document.getElementById('cat-min').value,10),idade_max:parseInt(document.getElementById('cat-max').value,10),valor_adicional:parseFloat(document.getElementById('cat-adicional').value)};try{await jsonFetch(id?'/api/faixas_etarias/'+id:'/api/faixas_etarias',{method:id?'PUT':'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});toast(id?'Categoria atualizada.':'Categoria salva.','success');limparCategoriaForm();carregarCategorias();}catch(e){toast(e.message,'error');}});
document.getElementById('cat-cancel').onclick=limparCategoriaForm;

async function carregarReservas(){
  const [rows,quartos,hospedes,faixas]=await Promise.all([jsonFetch('/api/reservas'),jsonFetch('/api/quartos'),jsonFetch('/api/hospedes'),jsonFetch('/api/faixas_etarias')]);
  state.reservas=rows||[];state.quartos=quartos||[];state.hospedes=hospedes||[];state.faixas=faixas||[];
  popularSelect('r-quarto-num',state.quartos.filter(x=>x.status!=='MANUTENCAO'),null,x=>x.numero+' — '+x.tipo,x=>x.numero);
  popularSelect('r-hospede-id',state.hospedes,null,x=>x.nome,x=>x.id);preencherFaixas();
  const tb=document.getElementById('tabela-reservas');tb.innerHTML='';
  if(!state.reservas.length){tb.innerHTML='<tr><td colspan="8" class="empty">Nenhuma reserva cadastrada.</td></tr>';return;}
  state.reservas.forEach(r=>{const tr=document.createElement('tr');const pagado=String(r.status_pagamento).toUpperCase()==='PAGO';const cancelada=String(r.status).toUpperCase()==='CANCELADA';tr.innerHTML='<td>'+r.id+'</td><td>'+escapar(r.hospede_nome||'Não informado')+'</td><td><strong>'+escapar(r.quarto_numero)+'</strong></td><td>'+escapar(r.check_in)+' até '+escapar(r.check_out)+'</td><td>'+r.diarias+'</td><td>'+moeda(r.valor_total)+'</td><td>'+badgeStatus(r.status_pagamento)+'</td><td><div class="row-actions">'+(!cancelada?'<button class="btn btn-secondary" onclick="editarReserva('+r.id+')">Editar</button>':'')+(!cancelada?'<button class="btn '+(pagado?'btn-warning':'btn-success')+'" onclick="alterarPagamentoReserva('+r.id+','+(pagado?'false':'true')+')">'+(pagado?'Não pago':'Pagou')+'</button>':'')+(!cancelada?'<button class="btn btn-danger" onclick="cancelarReserva('+r.id+')">Cancelar</button>':'')+'</div></td>';tb.appendChild(tr);});
}
function limparReservaForm(){document.getElementById('form-reserva').reset();document.getElementById('r-edit-id').value='';document.getElementById('r-cancel').classList.add('hidden');document.getElementById('r-submit').textContent='Criar reserva';document.getElementById('reserva-form-title').textContent='Nova reserva';preencherFaixas();}
function editarReserva(id){const r=state.reservas.find(x=>x.id===id);if(!r)return;switchTab('reservas');document.getElementById('r-edit-id').value=id;document.getElementById('r-hospede-id').value=r.hospede_id;document.getElementById('r-quarto-num').value=r.quarto_numero;document.getElementById('r-checkin').value=r.check_in;document.getElementById('r-checkout').value=r.check_out;document.getElementById('r-cancel').classList.remove('hidden');document.getElementById('r-submit').textContent='Salvar alterações';document.getElementById('reserva-form-title').textContent='Editar reserva #'+id;}
async function alterarPagamentoReserva(id,pago){const forma=pago?(prompt('Forma de pagamento (PIX, cartão, dinheiro etc.):','PIX')||'Não informado'):'Não informado';if(pago&&!confirm('Confirmar que a reserva foi paga e lançar a entrada no caixa?'))return;if(!pago&&!confirm('Marcar a reserva como não paga e remover a entrada automática do caixa?'))return;try{await jsonFetch('/api/reservas/'+id+'/pagamento',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({status:pago?'PAGO':'PENDENTE',forma_pagamento:forma})});toast('Pagamento da reserva atualizado.','success');carregarReservas();}catch(e){toast(e.message,'error');}}
async function cancelarReserva(id){if(!confirm('Cancelar esta reserva? O pagamento automático, se houver, será retirado do caixa.'))return;try{await jsonFetch('/api/reservas/'+id+'/cancelar',{method:'PUT'});toast('Reserva cancelada.','success');carregarReservas();}catch(e){toast(e.message,'error');}}
document.getElementById('form-reserva').addEventListener('submit',async e=>{e.preventDefault();const id=document.getElementById('r-edit-id').value;const comps=[...document.querySelectorAll('.faixa-input')].map(x=>({faixa_id:parseInt(x.dataset.id,10),quantidade:parseInt(x.value||'0',10)}));const body={hospede_id:parseInt(document.getElementById('r-hospede-id').value,10),quarto_numero:document.getElementById('r-quarto-num').value,check_in:document.getElementById('r-checkin').value,check_out:document.getElementById('r-checkout').value,composicao:comps};try{const d=await jsonFetch(id?'/api/reservas/'+id:'/api/reservas',{method:id?'PUT':'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});toast((id?'Reserva atualizada. ':'Reserva criada. ')+moeda(d.valor_total),'success');limparReservaForm();carregarReservas();}catch(e){toast(e.message,'error');}});
document.getElementById('r-cancel').onclick=limparReservaForm;

async function carregarServicos(){
  state.servicos=await jsonFetch('/api/servicos')||[];
  const tb=document.getElementById('tabela-servicos');tb.innerHTML='';
  state.servicos.forEach(s=>{const tr=document.createElement('tr');tr.innerHTML='<td>'+escapar(s.nome)+'</td><td>'+escapar(s.categoria)+'</td><td>'+moeda(s.preco)+'</td><td>'+escapar(s.unidade)+'</td><td>'+badgeStatus(s.ativo?'ATIVO':'BLOQUEADO')+'</td><td><div class="row-actions"><button class="btn btn-secondary" onclick="editarServico('+s.id+')">Editar</button><button class="btn btn-danger" onclick="desativarServico('+s.id+')">Desativar</button></div></td>';tb.appendChild(tr);});
  popularSelect('p-servico',state.servicos.filter(x=>x.ativo),'Selecionar serviço',x=>x.nome+' — '+moeda(x.preco),x=>x.id);
}
function limparServicoForm(){document.getElementById('form-servico').reset();document.getElementById('s-edit-id').value='';document.getElementById('s-categoria').value='Diversos';document.getElementById('s-unidade').value='unidade';document.getElementById('s-cancel').classList.add('hidden');document.getElementById('s-submit').textContent='Salvar serviço';document.getElementById('servico-form-title').textContent='Novo serviço';}
function editarServico(id){const s=state.servicos.find(x=>x.id===id);if(!s)return;switchTab('servicos');document.getElementById('s-edit-id').value=id;document.getElementById('s-nome').value=s.nome;document.getElementById('s-categoria').value=s.categoria;document.getElementById('s-unidade').value=s.unidade;document.getElementById('s-preco').value=s.preco;document.getElementById('s-cancel').classList.remove('hidden');document.getElementById('s-submit').textContent='Salvar alterações';document.getElementById('servico-form-title').textContent='Editar serviço';}
async function desativarServico(id){if(!confirm('Desativar este serviço? Pedidos antigos continuam registrados.'))return;try{await jsonFetch('/api/servicos/'+id,{method:'DELETE'});toast('Serviço desativado.','success');carregarServicos();}catch(e){toast(e.message,'error');}}
document.getElementById('form-servico').addEventListener('submit',async e=>{e.preventDefault();const id=document.getElementById('s-edit-id').value;const body={nome:document.getElementById('s-nome').value,categoria:document.getElementById('s-categoria').value,unidade:document.getElementById('s-unidade').value,preco:parseFloat(document.getElementById('s-preco').value),ativo:1};try{await jsonFetch(id?'/api/servicos/'+id:'/api/servicos',{method:id?'PUT':'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});toast(id?'Serviço atualizado.':'Serviço criado.','success');limparServicoForm();carregarServicos();}catch(e){toast(e.message,'error');}});
document.getElementById('s-cancel').onclick=limparServicoForm;
document.getElementById('p-servico').addEventListener('change',()=>{const s=state.servicos.find(x=>String(x.id)===document.getElementById('p-servico').value);if(s){document.getElementById('p-item').value=s.nome;document.getElementById('p-preco').value=s.preco;}});
async function carregarPedidos(){state.pedidos=await jsonFetch('/api/pedidos')||[];const tb=document.getElementById('tabela-pedidos');tb.innerHTML='';if(!state.pedidos.length){tb.innerHTML='<tr><td colspan="9" class="empty">Nenhum pedido lançado.</td></tr>';return;}state.pedidos.forEach(p=>{const pago=String(p.status_pagamento)==='PAGO';const cancel=String(p.status)==='CANCELADO';const total=Number(p.quantidade||0)*Number(p.preco_unitario||0);const tr=document.createElement('tr');tr.innerHTML='<td>'+dataHora(p.solicitado_em)+'</td><td>'+escapar(p.quarto_numero||'-')+'</td><td>'+escapar(p.hospede_nome||'-')+'</td><td>'+escapar(p.item)+'</td><td>'+p.quantidade+'</td><td>'+moeda(total)+'</td><td>'+badgeStatus(p.status)+'</td><td>'+badgeStatus(p.status_pagamento)+'</td><td><div class="row-actions">'+(!cancel?'<button class="btn btn-secondary" onclick="alterarStatusPedido('+p.id+')">Status</button>':'')+(!cancel?'<button class="btn '+(pago?'btn-warning':'btn-success')+'" onclick="alterarPagamentoPedido('+p.id+','+(pago?'false':'true')+')">'+(pago?'Não pago':'Pagou')+'</button>':'')+'</div></td>';tb.appendChild(tr);});}
async function alterarStatusPedido(id){const status=prompt('Novo status: ABERTO, EM_PREPARO, ENTREGUE ou CANCELADO','ENTREGUE');if(!status)return;try{await jsonFetch('/api/pedidos/'+id+'/status',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({status:status})});toast('Status do pedido atualizado.','success');carregarPedidos();}catch(e){toast(e.message,'error');}}
async function alterarPagamentoPedido(id,pago){if(pago&&!confirm('Confirmar pagamento e lançar a entrada no caixa?'))return;if(!pago&&!confirm('Marcar como não pago e remover a entrada automática do caixa?'))return;try{await jsonFetch('/api/pedidos/'+id+'/pagamento',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({status:pago?'PAGO':'PENDENTE',forma_pagamento:pago?(prompt('Forma de pagamento:','PIX')||'Não informado'):'Não informado'})});toast('Pagamento do pedido atualizado.','success');carregarPedidos();}catch(e){toast(e.message,'error');}}
document.getElementById('form-pedido').addEventListener('submit',async e=>{e.preventDefault();const body={quarto_id:parseInt(document.getElementById('p-quarto').value,10),hospede_id:document.getElementById('p-hospede').value||null,servico_id:document.getElementById('p-servico').value||null,item:document.getElementById('p-item').value,quantidade:parseFloat(document.getElementById('p-qtd').value),preco_unitario:parseFloat(document.getElementById('p-preco').value),descricao:document.getElementById('p-desc').value};try{const d=await jsonFetch('/api/pedidos',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});toast('Pedido lançado. Total '+moeda(d.total),'success');document.getElementById('form-pedido').reset();document.getElementById('p-qtd').value=1;document.getElementById('p-preco').value=0;carregarPedidos();}catch(e){toast(e.message,'error');}});

async function carregarOrdens(){state.ordens=await jsonFetch('/api/ordens')||[];const tb=document.getElementById('tabela-os');tb.innerHTML='';if(!state.ordens.length){tb.innerHTML='<tr><td colspan="8" class="empty">Nenhuma ordem de serviço.</td></tr>';return;}state.ordens.forEach(o=>{const tr=document.createElement('tr');tr.innerHTML='<td>'+o.id+'</td><td><strong>'+escapar(o.quarto)+'</strong></td><td>'+escapar(o.hospede_nome||'-')+'</td><td>'+escapar(o.tipo)+'</td><td>'+badgeStatus(o.prioridade)+'</td><td>'+escapar(o.responsavel_nome||'A definir')+'</td><td>'+badgeStatus(o.status)+'</td><td><div class="row-actions"><button class="btn btn-secondary" onclick="editarOrdem('+o.id+')">Editar</button><button class="btn btn-primary" onclick="avancarOrdem('+o.id+')">Status</button><button class="btn btn-danger" onclick="excluirOrdem('+o.id+')">Excluir</button></div></td>';tb.appendChild(tr);});
  await carregarUsuariosParaOS();
}
async function carregarUsuariosParaOS(){if(CONTEXTO_USUARIO.role==='platform_admin')return;try{const rows=await jsonFetch('/api/usuarios');state.usuarios=rows||[];popularSelect('os-responsavel',state.usuarios.filter(x=>x.ativo),'A definir',x=>x.nome+' — '+x.role_label,x=>x.id);}catch(e){state.usuarios=[];}}
function limparOsForm(){document.getElementById('form-os').reset();document.getElementById('os-edit-id').value='';document.getElementById('os-cancel').classList.add('hidden');document.getElementById('os-submit').textContent='Criar OS';document.getElementById('os-form-title').textContent='Nova ordem de serviço';}
function editarOrdem(id){const o=state.ordens.find(x=>x.id===id);if(!o)return;switchTab('ordens');document.getElementById('os-edit-id').value=id;document.getElementById('os-quarto').value=o.quarto_id;document.getElementById('os-hospede').value=o.hospede_id||'';document.getElementById('os-tipo').value=o.tipo;document.getElementById('os-prioridade').value=o.prioridade;document.getElementById('os-responsavel').value=o.responsavel_id||'';document.getElementById('os-desc').value=o.descricao;document.getElementById('os-cancel').classList.remove('hidden');document.getElementById('os-submit').textContent='Salvar alterações';document.getElementById('os-form-title').textContent='Editar OS #'+id;}
async function avancarOrdem(id){const s=prompt('Novo status: PENDENTE, EM_ANDAMENTO, CONCLUIDA ou CANCELADA','CONCLUIDA');if(!s)return;try{await jsonFetch('/api/ordens/'+id+'/status',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({status:s})});toast('Status da OS atualizado.','success');carregarOrdens();}catch(e){toast(e.message,'error');}}
async function excluirOrdem(id){if(!confirm('Excluir esta OS?'))return;try{await jsonFetch('/api/ordens/'+id,{method:'DELETE'});toast('OS removida.','success');carregarOrdens();}catch(e){toast(e.message,'error');}}
document.getElementById('form-os').addEventListener('submit',async e=>{e.preventDefault();const id=document.getElementById('os-edit-id').value;const body={quarto_id:parseInt(document.getElementById('os-quarto').value,10),hospede_id:document.getElementById('os-hospede').value||null,tipo:document.getElementById('os-tipo').value,prioridade:document.getElementById('os-prioridade').value,responsavel_id:document.getElementById('os-responsavel').value||null,descricao:document.getElementById('os-desc').value};try{await jsonFetch(id?'/api/ordens/'+id:'/api/ordens',{method:id?'PUT':'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});toast(id?'OS atualizada.':'OS criada.','success');limparOsForm();carregarOrdens();}catch(e){toast(e.message,'error');}});
document.getElementById('os-cancel').onclick=limparOsForm;

async function carregarEquipe(){if(CONTEXTO_USUARIO.role!=='admin')return;state.usuarios=await jsonFetch('/api/usuarios')||[];const tb=document.getElementById('tabela-equipe');tb.innerHTML='';state.usuarios.forEach(u=>{const tr=document.createElement('tr');tr.innerHTML='<td>'+escapar(u.nome||u.username)+'</td><td>'+escapar(u.username)+'</td><td>'+escapar(u.role_label)+'</td><td>'+escapar(dataHora(u.ultimo_login))+'</td><td>'+badgeStatus(u.ativo?'ATIVO':'BLOQUEADO')+'</td><td><div class="row-actions"><button class="btn btn-secondary" onclick="editarUsuario('+u.id+')">Editar</button>'+(u.ativo?'<button class="btn btn-danger" onclick="bloquearUsuario('+u.id+')">Bloquear</button>':'')+'</div></td>';tb.appendChild(tr);});}
function limparUsuarioForm(){document.getElementById('form-user').reset();document.getElementById('u-edit-id').value='';document.getElementById('u-username').disabled=false;document.getElementById('u-password').required=true;document.getElementById('u-ativo').value='1';document.getElementById('u-cancel').classList.add('hidden');document.getElementById('u-submit').textContent='Criar acesso';document.getElementById('user-form-title').textContent='Novo acesso';}
function editarUsuario(id){const u=state.usuarios.find(x=>x.id===id);if(!u)return;switchTab('equipe');document.getElementById('u-edit-id').value=id;document.getElementById('u-nome').value=u.nome||'';document.getElementById('u-username').value=u.username;document.getElementById('u-username').disabled=true;document.getElementById('u-role').value=u.role;document.getElementById('u-email').value=u.email||'';document.getElementById('u-password').value='';document.getElementById('u-password').required=false;document.getElementById('u-ativo').value=u.ativo?'1':'0';document.getElementById('u-cancel').classList.remove('hidden');document.getElementById('u-submit').textContent='Salvar alterações';document.getElementById('user-form-title').textContent='Editar acesso';}
async function bloquearUsuario(id){if(!confirm('Bloquear este acesso?'))return;try{await jsonFetch('/api/usuarios/'+id,{method:'DELETE'});toast('Usuário bloqueado.','success');carregarEquipe();}catch(e){toast(e.message,'error');}}
document.getElementById('form-user').addEventListener('submit',async e=>{e.preventDefault();const id=document.getElementById('u-edit-id').value;const body={nome:document.getElementById('u-nome').value,username:document.getElementById('u-username').value,role:document.getElementById('u-role').value,email:document.getElementById('u-email').value,ativo:document.getElementById('u-ativo').value==='1',password:document.getElementById('u-password').value};try{await jsonFetch(id?'/api/usuarios/'+id:'/api/usuarios',{method:id?'PUT':'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});toast(id?'Acesso atualizado.':'Acesso criado.','success');limparUsuarioForm();carregarEquipe();}catch(e){toast(e.message,'error');}});
document.getElementById('u-cancel').onclick=limparUsuarioForm;

async function carregarEstoque(){state.estoque=await jsonFetch('/api/estoque')||[];const tb=document.getElementById('tabela-estoque');tb.innerHTML='';state.estoque.forEach(x=>{const tr=document.createElement('tr');tr.innerHTML='<td>'+escapar(x.item)+'</td><td>'+escapar(x.categoria)+'</td><td>'+x.quantidade+'</td><td>'+moeda(x.preco_unitario)+'</td><td><div class="row-actions"><button class="btn btn-secondary" onclick="editarEstoque('+x.id+')">Editar</button><button class="btn btn-danger" onclick="excluirEstoque('+x.id+')">Excluir</button></div></td>';tb.appendChild(tr);});}
function limparEstoqueForm(){document.getElementById('form-estoque').reset();document.getElementById('e-edit-id').value='';document.getElementById('e-cancel').classList.add('hidden');document.getElementById('e-submit').textContent='Adicionar item';document.getElementById('estoque-form-title').textContent='Novo item de estoque';}
function editarEstoque(id){const x=state.estoque.find(s=>s.id===id);if(!x)return;switchTab('estoque');document.getElementById('e-edit-id').value=id;document.getElementById('e-item').value=x.item;document.getElementById('e-cat').value=x.categoria;document.getElementById('e-qtd').value=x.quantidade;document.getElementById('e-preco').value=x.preco_unitario;document.getElementById('e-cancel').classList.remove('hidden');document.getElementById('e-submit').textContent='Salvar alterações';document.getElementById('estoque-form-title').textContent='Editar item';}
async function excluirEstoque(id){if(!confirm('Excluir este item?'))return;try{await jsonFetch('/api/estoque/'+id,{method:'DELETE'});toast('Item removido.','success');carregarEstoque();}catch(e){toast(e.message,'error');}}
document.getElementById('form-estoque').addEventListener('submit',async e=>{e.preventDefault();const id=document.getElementById('e-edit-id').value;const body={item:document.getElementById('e-item').value,categoria:document.getElementById('e-cat').value,quantidade:parseInt(document.getElementById('e-qtd').value,10),preco_unitario:parseFloat(document.getElementById('e-preco').value)};try{await jsonFetch(id?'/api/estoque/'+id:'/api/estoque',{method:id?'PUT':'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});toast(id?'Estoque atualizado.':'Item adicionado.','success');limparEstoqueForm();carregarEstoque();}catch(e){toast(e.message,'error');}});
document.getElementById('e-cancel').onclick=limparEstoqueForm;

async function carregarFinanceiro(){state.financeiro=await jsonFetch('/api/financeiro')||[];const tb=document.getElementById('tabela-financeiro');tb.innerHTML='';state.financeiro.forEach(x=>{const tr=document.createElement('tr');tr.innerHTML='<td>'+escapar(x.data)+'</td><td>'+badgeStatus(x.tipo)+'</td><td>'+escapar(x.descricao)+'</td><td>'+escapar(x.categoria)+'</td><td>'+moeda(x.valor)+'</td><td>'+escapar(x.origem_tipo||'Manual')+'</td><td>'+(x.origem_tipo?'Automático':'<button class="btn btn-secondary" onclick="editarFinanceiro('+x.id+')">Editar</button>')+'</td>';tb.appendChild(tr);});}
function limparFinanceiroForm(){document.getElementById('form-fin').reset();document.getElementById('f-edit-id').value='';document.getElementById('f-cat').value='Geral';document.getElementById('f-cancel').classList.add('hidden');document.getElementById('f-submit').textContent='Lançar';document.getElementById('fin-form-title').textContent='Novo lançamento';}
function editarFinanceiro(id){const x=state.financeiro.find(s=>s.id===id);if(!x||x.origem_tipo)return;switchTab('financeiro');document.getElementById('f-edit-id').value=id;document.getElementById('f-tipo').value=x.tipo;document.getElementById('f-desc').value=x.descricao;document.getElementById('f-valor').value=x.valor;document.getElementById('f-cat').value=x.categoria;document.getElementById('f-cancel').classList.remove('hidden');document.getElementById('f-submit').textContent='Salvar alterações';document.getElementById('fin-form-title').textContent='Editar lançamento';}
document.getElementById('form-fin').addEventListener('submit',async e=>{e.preventDefault();const id=document.getElementById('f-edit-id').value;const body={tipo:document.getElementById('f-tipo').value,descricao:document.getElementById('f-desc').value,valor:parseFloat(document.getElementById('f-valor').value),categoria:document.getElementById('f-cat').value};try{await jsonFetch(id?'/api/financeiro/'+id:'/api/financeiro',{method:id?'PUT':'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});toast(id?'Lançamento atualizado.':'Lançamento realizado.','success');limparFinanceiroForm();carregarFinanceiro();}catch(e){toast(e.message,'error');}});
document.getElementById('f-cancel').onclick=limparFinanceiroForm;

async function carregarRelatorios(){
  const d=await jsonFetch('/api/relatorios');if(!d)return;
  const el=document.getElementById('relatorio-metricas');
  const arr=[['Quartos',d.total_quartos,'Total cadastrado'],['Ocupados',d.quartos_ocupados,'Hoje'],['Taxa de ocupação',Number(d.taxa_ocupacao).toFixed(2)+'%','Hoje'],['Receita paga',moeda(d.receita_total),'Hospedagem + serviços'],['Hospedagem paga',moeda(d.receita_hospedagem),'Reservas'],['Serviços pagos',moeda(d.receita_servicos),'Pedidos'],['ADR',moeda(d.adr),'Diária média paga'],['RevPAR',moeda(d.revpar),'Indicador']];el.innerHTML=arr.map(x=>'<div class="metric"><div class="metric-label">'+escapar(x[0])+'</div><div class="metric-value">'+escapar(x[1])+'</div><div class="metric-note">'+escapar(x[2])+'</div></div>').join('');
}
async function carregarPainel(){
  const el=document.getElementById('tab-painel');
  el.innerHTML='<div class="metrics" id="painel-metrics"></div><div class="card"><div class="card-header"><div><h2 class="card-title">Operação</h2><p class="card-help">Acesse rapidamente reservas, pedidos e ordens de serviço.</p></div></div><div class="toolbar"><button class="btn btn-primary" onclick="switchTab('reservas')">Abrir reservas</button><button class="btn btn-secondary" onclick="switchTab('servicos')">Abrir pedidos</button><button class="btn btn-secondary" onclick="switchTab('ordens')">Abrir ordens de serviço</button></div></div>';
  const d=await jsonFetch('/api/relatorios');const s=await jsonFetch('/api/assinatura');if(!d)return;
  const m=[['Quartos',d.total_quartos],['Ocupados',d.quartos_ocupados],['Ocupação',Number(d.taxa_ocupacao).toFixed(2)+'%'],['Receita paga',moeda(d.receita_total)]];
  document.getElementById('painel-metrics').innerHTML=m.map(x=>'<div class="metric"><div class="metric-label">'+escapar(x[0])+'</div><div class="metric-value">'+escapar(x[1])+'</div></div>').join('');
  if(s){const card=document.createElement('div');card.className='notice '+(s.ativo?'success':'danger');card.textContent='Plano '+(s.plano_nome||'-')+' | status: '+(s.status||'-')+(s.periodo_fim?' | validade: '+s.periodo_fim:'');document.getElementById('tab-painel').insertBefore(card,document.getElementById('painel-metrics'));}
}
async function carregarIntegracoes(){
  const d=await jsonFetch('/api/integracoes');if(!d)return;
  document.getElementById('int-booking').value=d.booking_url||'';document.getElementById('int-airbnb').value=d.airbnb_url||'';document.getElementById('int-expedia').value=d.expedia_url||'';document.getElementById('int-hoteis').value=d.hoteis_url||'';document.getElementById('int-site').value=d.website_url||'';document.getElementById('int-maps-url').value=d.maps_url||'';document.getElementById('int-maps-nome').value=d.maps_nome||'';document.getElementById('int-place-id').value=d.maps_place_id||'';document.getElementById('int-endereco').value=d.endereco||'';document.getElementById('int-lat').value=d.latitude??'';document.getElementById('int-lng').value=d.longitude??'';document.getElementById('int-webhook-url').value=d.webhook_asaas_url||'';renderMapa(d.maps_embed_url);
  await carregarPlanos();
}
async function carregarPlanos(){state.planos=await jsonFetch('/api/planos')||[];const el=document.getElementById('saas-plano');el.innerHTML=state.planos.map(p=>'<option value="'+p.id+'">'+escapar(p.nome)+' — '+moeda(p.preco_mensal)+'/mês</option>').join('');state.sub=await jsonFetch('/api/assinatura');if(state.sub){document.getElementById('saas-status').value=state.sub.status||'';document.getElementById('saas-fim').value=state.sub.periodo_fim||state.sub.trial_ate||'';}}
async function contratarPlano(){const id=parseInt(document.getElementById('saas-plano').value,10);try{const d=await jsonFetch('/api/assinatura/checkout',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({plano_id:id})});if(d&&d.checkout_url)window.open(d.checkout_url,'_blank','noopener,noreferrer');else toast(d.mensagem||'Checkout criado.','success');}catch(e){toast(e.message,'error');}}
document.getElementById('form-integracoes').addEventListener('submit',async e=>{e.preventDefault();const body={booking_url:document.getElementById('int-booking').value.trim(),airbnb_url:document.getElementById('int-airbnb').value.trim(),expedia_url:document.getElementById('int-expedia').value.trim(),hoteis_url:document.getElementById('int-hoteis').value.trim(),website_url:document.getElementById('int-site').value.trim(),maps_url:document.getElementById('int-maps-url').value.trim(),maps_nome:document.getElementById('int-maps-nome').value.trim(),maps_place_id:document.getElementById('int-place-id').value.trim(),endereco:document.getElementById('int-endereco').value.trim(),latitude:document.getElementById('int-lat').value||null,longitude:document.getElementById('int-lng').value||null};try{const d=await jsonFetch('/api/integracoes',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});toast(d.mensagem,'success');renderMapa(d.integracao?.maps_embed_url||null);}catch(e){toast(e.message,'error');}});
async function pesquisarGoogleMaps(){const q=(document.getElementById('int-maps-nome').value||document.getElementById('int-endereco').value||'').trim();if(q.length<3){toast('Informe nome ou endereço.','error');return;}try{const d=await jsonFetch('/api/integracoes/maps/pesquisar',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({q})});const box=document.getElementById('resultado-maps');box.innerHTML='';(d.resultados||[]).forEach(p=>{const b=document.createElement('button');b.type='button';b.className='btn btn-secondary';b.style.margin='4px';b.textContent=(p.nome||'Local')+' — '+(p.endereco||'');b.onclick=()=>{document.getElementById('int-maps-nome').value=p.nome||'';document.getElementById('int-place-id').value=p.id||'';document.getElementById('int-endereco').value=p.endereco||'';document.getElementById('int-lat').value=p.latitude??'';document.getElementById('int-lng').value=p.longitude??'';document.getElementById('int-maps-url').value=p.maps_url||'';};box.appendChild(b);});if(!(d.resultados||[]).length)box.textContent='Nenhum local encontrado.';}catch(e){toast(e.message,'error');}}
function renderMapa(url){const box=document.getElementById('mapa-hotel');box.innerHTML='';if(!url){box.className='notice info';box.textContent='Mapa incorporado disponível após configurar a chave do Google Maps no servidor.';return;}box.className='';const f=document.createElement('iframe');f.src=url;f.width='100%';f.height='350';f.style.border='0';f.loading='lazy';f.allowFullscreen=true;f.referrerPolicy='strict-origin-when-cross-origin';box.appendChild(f);}
function preencherWhatsApp(){document.getElementById('wa-msg').value=document.getElementById('wa-template').value;}
document.getElementById('wa-template').addEventListener('change',preencherWhatsApp);
preencherWhatsApp();
function enviarWhatsApp(){const tel=document.getElementById('wa-tel').value.replace(/\D/g,'');if(tel.length<10){toast('Informe um telefone válido com DDD.','error');return;}window.open('https://wa.me/'+tel+'?text='+encodeURIComponent(document.getElementById('wa-msg').value),'_blank','noopener,noreferrer');}

async function carregarPlataforma(){
  const aviso=document.getElementById('plataforma-aviso');const tb=document.getElementById('tabela-plataforma');aviso.className='notice info';aviso.textContent='Atualizando clientes...';
  try{
    const [hotels,plans]=await Promise.all([jsonFetch('/api/platform/hoteis'),jsonFetch('/api/planos')]);state.planos=plans||[];tb.innerHTML='';
    (hotels||[]).forEach(h=>{
      const adminNames=(h.admins||[]).map(a=>a.nome||a.username).join(', ')||'Sem administrador ativo';
      const sub=h.assinatura||{};const status=h.bloqueado?'BLOQUEADO':(sub.status||'SEM ASSINATURA');const validade=sub.periodo_fim||sub.trial_ate||'-';
      const tr=document.createElement('tr');
      const planSel=state.planos.map(p=>'<option value="'+p.id+'" '+(String(p.id)===String(sub.plano_id)?'selected':'')+'>'+escapar(p.nome)+'</option>').join('');
      const stSel=['ATIVA','TESTE','SUSPENSA','CANCELADA'].map(x=>'<option value="'+x+'" '+(String(sub.status||'')===x?'selected':'')+'>'+x+'</option>').join('');
      tr.innerHTML='<td><strong>'+escapar(h.nome)+'</strong><div class="small">'+escapar(h.local||'-')+'</div></td><td>'+escapar(adminNames)+'</td><td><select id="plan-'+h.id+'">'+planSel+'</select></td><td><input id="dias-'+h.id+'" type="number" min="0" max="3660" value="'+(sub.periodo_fim?Math.max(0,Math.round((new Date(sub.periodo_fim)-new Date())/86400000)):30)+'" style="width:90px;padding:7px;border:1px solid #ccd3dd;border-radius:7px"> dias</td><td><span class="platform-status '+(h.bloqueado?'platform-blocked':'platform-open')+'">'+escapar(status)+'</span></td><td><div class="row-actions"><select id="status-'+h.id+'" style="padding:7px;border:1px solid #ccd3dd;border-radius:7px">'+stSel+'</select><button class="btn btn-primary" onclick="salvarAssinaturaPlataforma('+h.id+')">Salvar</button><button class="btn '+(h.bloqueado?'btn-success':'btn-danger')+'" onclick="alternarBloqueio('+h.id+','+(h.bloqueado?'false':'true')+')">'+(h.bloqueado?'Liberar':'Bloquear')+'</button></div></td>';
      tb.appendChild(tr);
    });
    aviso.className='notice success';aviso.textContent=(hotels||[]).length+' hotel(is) encontrado(s).';
  }catch(e){aviso.className='notice danger';aviso.textContent=e.message;}
}
async function alternarBloqueio(id,bloquear){const motivo=bloquear?(prompt('Motivo do bloqueio:','Pagamento pendente')||'Pagamento pendente'):'';if(bloquear&&!confirm('Bloquear o acesso deste hotel?'))return;if(!bloquear&&!confirm('Liberar o acesso deste hotel?'))return;try{await jsonFetch('/api/platform/hoteis/'+id+'/bloqueio',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({bloqueado:bloquear,motivo})});toast(bloquear?'Hotel bloqueado.':'Hotel liberado.','success');carregarPlataforma();}catch(e){toast(e.message,'error');}}
async function salvarAssinaturaPlataforma(id){const plano_id=parseInt(document.getElementById('plan-'+id).value,10),status=document.getElementById('status-'+id).value,dias=parseInt(document.getElementById('dias-'+id).value,10);try{await jsonFetch('/api/platform/assinaturas/'+id,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({plano_id,status,dias})});toast('Assinatura atualizada.','success');carregarPlataforma();}catch(e){toast(e.message,'error');}}

async function loadTab(tab){
  if(CONTEXTO_USUARIO.role==='platform_admin'){if(tab==='plataforma')await carregarPlataforma();return;}
  if(tab==='painel')await carregarPainel();
  else if(tab==='quartos'){await carregarQuartos();}
  else if(tab==='hospedes'){await carregarHospedes();}
  else if(tab==='categorias'){await carregarCategorias();}
  else if(tab==='reservas'){await carregarReservas();}
  else if(tab==='servicos'){await carregarBase();await carregarServicos();await carregarPedidos();}
  else if(tab==='ordens'){await carregarBase();await carregarOrdens();}
  else if(tab==='equipe'){await carregarEquipe();}
  else if(tab==='estoque'){await carregarEstoque();}
  else if(tab==='financeiro'){await carregarFinanceiro();}
  else if(tab==='relatorios'){await carregarRelatorios();}
  else if(tab==='integracoes'){await carregarIntegracoes();}
  else if(tab==='whatsapp'){preencherWhatsApp();}
}

renderNav();
switchTab(primeiraAba,false);
</script>
</body>
</html>'''


if __name__ == '__main__':
    init_db()
    app.run(host=os.getenv('HOST','0.0.0.0'), port=int(os.getenv('PORT','5000')), debug=os.getenv('FLASK_DEBUG','0').lower() in ('1','true','yes'))