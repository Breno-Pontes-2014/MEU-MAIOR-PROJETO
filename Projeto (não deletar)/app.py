import os
import datetime
import json
import hashlib
import re
import secrets
import time
import sqlite3
import urllib.parse
import urllib.request
import jwt
from functools import wraps
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, g
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

def load_local_env():
    """Carrega variáveis de .env local, sem substituir as definidas no sistema."""
    caminho=os.path.join(os.path.dirname(os.path.abspath(__file__)),'.env')
    try:
        with open(caminho,'r',encoding='utf-8-sig') as arquivo:
            for linha in arquivo:
                linha=linha.strip()
                if not linha or linha.startswith('#') or '=' not in linha: continue
                chave,_,valor=linha.partition('='); chave=chave.strip(); valor=valor.strip()
                if not chave or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',chave): continue
                if len(valor)>=2 and valor[0]==valor[-1] and valor[0] in ('"',"'"): valor=valor[1:-1]
                os.environ.setdefault(chave,valor)
    except FileNotFoundError:
        pass

load_local_env()

try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:
    psycopg = None
    dict_row = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'hotel.db')
DATABASE_URL = os.getenv('DATABASE_URL', '').strip()
SAAS_TIMEZONE_OFFSET = os.getenv('SAAS_TIMEZONE_OFFSET', '-03:00').strip()
JWT_SECRET_FILE = os.path.join(BASE_DIR, '.jwt_secret')
FLASK_SECRET_FILE = os.path.join(BASE_DIR, '.flask_secret')
TEMPLATES_DIR = os.path.join(BASE_DIR, 'templates')

def saas_local_now():
    try:
        if not re.fullmatch(r'[+-](?:0\d|1[0-4]):[0-5]\d',SAAS_TIMEZONE_OFFSET): raise ValueError
        sinal=-1 if SAAS_TIMEZONE_OFFSET.startswith('-') else 1
        horas,minutos=(int(x) for x in SAAS_TIMEZONE_OFFSET[1:].split(':',1))
        if horas==14 and minutos: raise ValueError
        zona=datetime.timezone(datetime.timedelta(minutes=sinal*(horas*60+minutos)))
    except (ValueError,IndexError):
        zona=datetime.timezone(datetime.timedelta(hours=-3))
    return datetime.datetime.now(zona)

def utc_now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

IS_PRODUCTION = (
    os.getenv('APP_ENV', '').strip().lower() == 'production'
    or os.getenv('FLASK_ENV', '').strip().lower() == 'production'
    or bool(os.getenv('RENDER', '').strip())
)
if IS_PRODUCTION:
    required_production_settings = ('DATABASE_URL', 'FLASK_SECRET_KEY', 'JWT_SECRET')
    missing_production_settings = [name for name in required_production_settings if not os.getenv(name, '').strip()]
    if missing_production_settings:
        raise RuntimeError('Configuração de produção incompleta: defina ' + ', '.join(missing_production_settings))
    if os.getenv('FLASK_SECRET_KEY', '').strip() == os.getenv('JWT_SECRET', '').strip():
        raise RuntimeError('FLASK_SECRET_KEY e JWT_SECRET devem ser valores diferentes.')

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

app.config['SECRET_KEY'] = get_or_create_secret('FLASK_SECRET_KEY', FLASK_SECRET_FILE)
JWT_SECRET = get_or_create_secret('JWT_SECRET', JWT_SECRET_FILE)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.getenv('SESSION_COOKIE_SECURE', '1' if IS_PRODUCTION else '0').lower() in ('1', 'true', 'yes'),
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=datetime.timedelta(hours=8),
    MAX_CONTENT_LENGTH=2 * 1024 * 1024
)

FORCE_HTTPS = os.getenv('FORCE_HTTPS', '1' if IS_PRODUCTION else '0').lower() in ('1', 'true', 'yes')
LOGIN_MAX_FAILURES = 10
LOGIN_LOCK_SECONDS = 15 * 60

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
    'gerente': {'rooms.view','rooms.manage','guests.view','guests.manage','categories.view','categories.manage','reservations.view','reservations.manage','reservations.pay','stock.view','stock.manage','finance.view','finance.manage','orders.view','orders.manage','services.view','services.manage','requests.view','requests.manage','reports.view','whatsapp.use','support.view'},
    'recepcao': {'rooms.view','guests.view','guests.manage','reservations.view','reservations.manage','reservations.pay','orders.view','orders.manage','services.view','requests.view','requests.manage','whatsapp.use','support.view'},
    'limpeza': {'rooms.view','orders.view','orders.manage','requests.view','requests.manage','support.view'},
    'manutencao': {'rooms.view','orders.view','orders.manage','requests.view','support.view'},
    'financeiro': {'rooms.view','guests.view','reservations.view','reservations.pay','finance.view','finance.manage','requests.view','requests.manage','reports.view','support.view'}
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
    'registrar_movimentacao_reserva':'reservations.manage',
    'api_integracoes':'integrations.view','salvar_integracoes':'integrations.manage','pesquisar_maps':'integrations.manage',
    'criar_checkout_asaas':'subscription.manage','api_assinatura':'subscription.view','api_assinatura_limites':'subscription.view','api_solicitar_plano':'subscription.manage',
    'listar_usuarios_hotel':'team.view','criar_usuario_hotel':'team.manage','editar_usuario_hotel':'team.manage','desativar_usuario_hotel':'team.manage',
    'listar_servicos':'services.view','criar_servico':'services.manage','editar_servico':'services.manage','deletar_servico':'services.manage',
    'listar_pedidos':'requests.view','criar_pedido':'requests.manage','editar_pedido':'requests.manage','atualizar_pedido_status':'requests.manage','marcar_pagamento_pedido':'requests.manage'
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
    conn=get_db()
    try:
        key_hash=hashlib.sha256(str(key).encode('utf-8')).hexdigest()
        info=conn.execute('SELECT failure_count,window_started,locked_until FROM login_failures WHERE key_hash=?',(key_hash,)).fetchone()
        if not info:
            return False
        now=time.time()
        if float(info['locked_until'] or 0)>now:
            return True
        if now-float(info['window_started'] or 0)>=LOGIN_LOCK_SECONDS:
            conn.execute('DELETE FROM login_failures WHERE key_hash=?',(key_hash,)); conn.commit()
        return False
    finally:
        conn.close()

def register_login_failure(key):
    conn=get_db()
    try:
        key_hash=hashlib.sha256(str(key).encode('utf-8')).hexdigest()
        now=time.time()
        info=conn.execute('SELECT failure_count,window_started,locked_until FROM login_failures WHERE key_hash=?',(key_hash,)).fetchone()
        if not info or now-float(info['window_started'] or 0)>=LOGIN_LOCK_SECONDS or float(info['locked_until'] or 0)>0 and float(info['locked_until'])<=now:
            count=1; started=now; locked=0.0
        else:
            count=int(info['failure_count'] or 0)+1; started=float(info['window_started'] or now)
            locked=now+LOGIN_LOCK_SECONDS if count>=LOGIN_MAX_FAILURES else float(info['locked_until'] or 0)
        conn.execute('''INSERT INTO login_failures (key_hash,failure_count,window_started,locked_until) VALUES (?,?,?,?)
                        ON CONFLICT (key_hash) DO UPDATE SET failure_count=excluded.failure_count,window_started=excluded.window_started,locked_until=excluded.locked_until''',
                     (key_hash,count,started,locked))
        conn.commit()
    finally:
        conn.close()

def clear_login_failures(key):
    conn=get_db()
    try:
        key_hash=hashlib.sha256(str(key).encode('utf-8')).hexdigest()
        conn.execute('DELETE FROM login_failures WHERE key_hash=?',(key_hash,)); conn.commit()
    finally:
        conn.close()

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
        ('Hotel Principal', saas_local_now().date().isoformat(), 'Não informado')
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
    hoje = saas_local_now().date()
    trial_ate = hoje + datetime.timedelta(days=7)
    cursor.execute('''
        INSERT INTO assinaturas
        (hotel_id, plano_id, status, inicio, periodo_fim, trial_ate, gateway, atualizado_em)
        VALUES (?, ?, 'TESTE', ?, ?, ?, 'interno', ?)
    ''', (hotel_id, plano['id'], hoje.isoformat(), trial_ate.isoformat(), trial_ate.isoformat(), utc_now_iso()))

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
    key = os.getenv('GEOAPIFY_MAPS_API_KEY','').strip()
    if not key:
        return None
    try:
        lat = float(integracao.get('latitude'))
        lon = float(integracao.get('longitude'))
    except (TypeError, ValueError):
        return None
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        return None
    params = {'style':'osm-bright','width':800,'height':350,'zoom':15,
              'center':f'lonlat:{lon},{lat}','marker':f'lonlat:{lon},{lat};color:#e11d48;size:medium',
              'format':'png','apiKey':key}
    return 'https://maps.geoapify.com/v1/staticmap?' + urllib.parse.urlencode(params)

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
    hoje = saas_local_now().date()
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
        ('Travesseiro extra','Quarto',5.00,'unidade'),
        ('Cobertor extra','Quarto',10.00,'unidade'),
        ('Kit higiene','Quarto',8.00,'kit'),
        ('Berço','Quarto',20.00,'diária'),
        ('Chave ou cartão extra','Quarto',10.00,'unidade'),
        ('Estacionamento','Diversos',20.00,'diária'),
        ('Late check-out','Diversos',50.00,'reserva'),
        ('Secador de cabelo','Quarto',12.00,'diária'),
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
    if cursor.execute("SELECT id FROM usuarios WHERE LOWER(username)=LOWER(?) AND role='platform_admin' LIMIT 1",(username,)).fetchone():
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
                bloqueio_motivo TEXT,
                servicos_extras INTEGER NOT NULL DEFAULT 1,
                possui_estoque INTEGER NOT NULL DEFAULT 1,
                maps_api_status TEXT NOT NULL DEFAULT 'nao_tenho',
                maps_api_key TEXT
            )
        ''')
        add_column_if_missing(cursor,'hoteis','servicos_extras INTEGER NOT NULL DEFAULT 1')
        add_column_if_missing(cursor,'hoteis','possui_estoque INTEGER NOT NULL DEFAULT 1')
        add_column_if_missing(cursor,'hoteis',"maps_api_status TEXT NOT NULL DEFAULT 'nao_tenho'")
        add_column_if_missing(cursor,'hoteis','maps_api_key TEXT')
        add_column_if_missing(cursor,'hoteis','whatsapp_telefone TEXT')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
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
                canal_origem TEXT NOT NULL DEFAULT 'Direto',
                checkin_realizado_em TEXT,
                checkout_realizado_em TEXT,
                cancelada_em TEXT,
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
            CREATE TABLE IF NOT EXISTS suporte_tickets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hotel_id INTEGER NOT NULL,
                assunto TEXT NOT NULL,
                prioridade TEXT NOT NULL DEFAULT 'NORMAL',
                status TEXT NOT NULL DEFAULT 'ABERTO',
                criado_por INTEGER,
                criado_em TEXT NOT NULL,
                atualizado_em TEXT NOT NULL,
                primeira_resposta_em TEXT,
                FOREIGN KEY (hotel_id) REFERENCES hoteis(id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS suporte_mensagens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ticket_id INTEGER NOT NULL,
                autor_id INTEGER,
                autor_role TEXT NOT NULL,
                mensagem TEXT NOT NULL,
                criado_em TEXT NOT NULL,
                FOREIGN KEY (ticket_id) REFERENCES suporte_tickets(id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS saas_module_usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hotel_id INTEGER NOT NULL,
                module TEXT NOT NULL,
                accessed_at TEXT NOT NULL,
                FOREIGN KEY (hotel_id) REFERENCES hoteis(id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS login_failures (
                key_hash TEXT PRIMARY KEY,
                failure_count INTEGER NOT NULL DEFAULT 0,
                window_started REAL NOT NULL,
                locked_until REAL NOT NULL DEFAULT 0
            )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_module_usage_date ON saas_module_usage(accessed_at,hotel_id,module)')
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
            CREATE TABLE IF NOT EXISTS checkout_assinaturas (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hotel_id INTEGER NOT NULL,
                plano_id INTEGER NOT NULL,
                external_reference TEXT NOT NULL UNIQUE,
                checkout_id TEXT UNIQUE,
                asaas_subscription_id TEXT,
                status TEXT NOT NULL DEFAULT 'PENDENTE',
                criado_em TEXT NOT NULL,
                atualizado_em TEXT NOT NULL,
                pago_em TEXT,
                FOREIGN KEY (hotel_id) REFERENCES hoteis(id),
                FOREIGN KEY (plano_id) REFERENCES planos(id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS asaas_pagamentos_processados (
                payment_id TEXT PRIMARY KEY,
                checkout_local_id INTEGER NOT NULL,
                processado_em TEXT NOT NULL
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
            ('usuarios','telefone TEXT'),('usuarios','whatsapp_notificacoes INTEGER NOT NULL DEFAULT 0'),
            ('reservas','pago_em TEXT'),('reservas','pago_por INTEGER'),('reservas','financeiro_id INTEGER'),('reservas','criada_por INTEGER'),
            ('reservas','observacoes TEXT'),('reservas',"canal_origem TEXT NOT NULL DEFAULT 'Não informado'"),
            ('reservas','checkin_realizado_em TEXT'),('reservas','checkout_realizado_em TEXT'),('reservas','cancelada_em TEXT'),
            ('fluxo_caixa','origem_tipo TEXT'),('fluxo_caixa','origem_id INTEGER'),('fluxo_caixa','forma_pagamento TEXT'),('fluxo_caixa','criado_por INTEGER'),
            ('ordens_servico','quarto_id INTEGER'),('ordens_servico','hospede_id INTEGER'),('ordens_servico','solicitante_id INTEGER'),('ordens_servico','responsavel_id INTEGER'),
            ('ordens_servico','prioridade TEXT NOT NULL DEFAULT \'NORMAL\''),('ordens_servico','aberta_em TEXT'),('ordens_servico','concluida_em TEXT'),('ordens_servico','valor REAL NOT NULL DEFAULT 0'),
            ('assinaturas','checkout_externo TEXT')
        ]:
            add_column_if_missing(cursor,table,coldef)

        ensure_planos(cursor)

        hotels=cursor.execute('SELECT id FROM hoteis ORDER BY id').fetchall()
        for row in hotels:
            hid=row['id']
            qtd=cursor.execute('SELECT COUNT(*) AS total FROM faixas_etarias WHERE hotel_id=?',(hid,)).fetchone()['total']
            if qtd==0:
                cursor.executemany('INSERT INTO faixas_etarias (nome,idade_min,idade_max,valor_adicional,hotel_id) VALUES (?,?,?,?,?)',
                                   [('Criança (até 11 anos)',0,11,0.0,hid),('Adulto',12,59,0.0,hid),('Idoso',60,120,0.0,hid)])
            ensure_subscription_for_hotel(cursor,hid)
            ensure_servicos_padrao(cursor,hid)

        cursor.execute('CREATE TABLE IF NOT EXISTS app_migrations (id TEXT PRIMARY KEY, applied_at TEXT NOT NULL)')
        if not cursor.execute("SELECT id FROM app_migrations WHERE id='usuarios_por_hotel_v1'").fetchone():
            if not cursor.connection.is_postgres:
                username_unique=False
                for idx in cursor.execute("PRAGMA index_list('usuarios')").fetchall():
                    if int(idx['unique']):
                        cols=[c['name'] for c in cursor.execute(f"PRAGMA index_info('{idx['name']}')").fetchall()]
                        if cols==['username']:
                            username_unique=True
                            break
                if username_unique:
                    cursor.execute('''CREATE TABLE usuarios_novo (
                        id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, nome TEXT,
                        password TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'recepcao', hotel_id INTEGER,
                        email TEXT, ativo INTEGER NOT NULL DEFAULT 1, ultimo_login TEXT, telefone TEXT,
                        whatsapp_notificacoes INTEGER NOT NULL DEFAULT 0,
                        FOREIGN KEY (hotel_id) REFERENCES hoteis(id))''')
                    cursor.execute('''INSERT INTO usuarios_novo (id,username,nome,password,role,hotel_id,email,ativo,ultimo_login,telefone,whatsapp_notificacoes)
                                      SELECT id,username,nome,password,role,hotel_id,email,ativo,ultimo_login,telefone,whatsapp_notificacoes FROM usuarios''')
                    cursor.execute('DROP TABLE usuarios')
                    cursor.execute('ALTER TABLE usuarios_novo RENAME TO usuarios')
            else:
                cursor.execute('ALTER TABLE usuarios DROP CONSTRAINT IF EXISTS usuarios_username_key')
            cursor.execute("INSERT INTO app_migrations (id,applied_at) VALUES (?,?)",('usuarios_por_hotel_v1',utc_now_iso()))
        ensure_platform_admin(cursor)
        if not cursor.execute("SELECT id FROM app_migrations WHERE id='servicos_precos_sugeridos_v1'").fetchone():
            precos_sugeridos={
                'Travesseiro extra':5.00,'Cobertor extra':10.00,'Kit higiene':8.00,
                'Berço':20.00,'Chave ou cartão extra':10.00,'Estacionamento':20.00,
                'Late check-out':50.00,'Secador de cabelo':12.00
            }
            for nome,preco in precos_sugeridos.items():
                cursor.execute('UPDATE servicos SET preco=? WHERE nome=? AND preco<=0',(preco,nome))
            cursor.execute('INSERT INTO app_migrations (id,applied_at) VALUES (?,?)',('servicos_precos_sugeridos_v1',utc_now_iso()))

        for table in TENANT_TABLES + ['servicos','pedidos_hospede']:
            cursor.execute(f'CREATE INDEX IF NOT EXISTS idx_{table}_hotel_id ON {table}(hotel_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_usuarios_hotel_id ON usuarios(hotel_id)')
        cursor.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_usuarios_hotel_username ON usuarios(hotel_id,LOWER(username)) WHERE hotel_id IS NOT NULL')
        cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_platform_admin_username ON usuarios(LOWER(username)) WHERE role='platform_admin'")
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_reservas_quarto_datas ON reservas(hotel_id,quarto_numero,check_in,check_out)')
        cursor.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_servicos_hotel_nome ON servicos(hotel_id,nome)')
        conn.commit()
    finally:
        conn.close()

# Gunicorn imports app:app, so database setup must also run on import.
init_db()

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
                token_user_id=data.get('user_id')
                if token_user_id is not None:
                    user=conn.execute('SELECT id,username,nome,role,hotel_id,ativo,email FROM usuarios WHERE id=? LIMIT 1',(token_user_id,)).fetchone()

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

@app.route('/index.html')
def legacy_index_page():
    return redirect(url_for('login'))

@app.route('/login.html')
def legacy_login_page():
    return redirect(url_for('login'))

@app.route('/cadastro.html')
def legacy_registration_page():
    return redirect(url_for('registro'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method=='POST':
        username=request.form.get('username','').strip()
        password=request.form.get('password','')
        if not check_csrf():
            return render_template('login.html',erro='Sessão expirada. Recarregue a página.',csrf_token=csrf_token())
        lock_key=f'{client_ip()}::{username.lower()}'
        if login_is_locked(lock_key):
            return render_template('login.html',erro='Muitas tentativas. Tente novamente em alguns minutos.',csrf_token=csrf_token())
        conn=get_db()
        try:
            users=conn.execute('SELECT * FROM usuarios WHERE LOWER(username)=LOWER(?) ORDER BY id',(username,)).fetchall()
            matches=[u for u in users if senha_compat(u['password'],password)]
            if len(matches)>1:
                return render_template('login.html',erro='Há contas com o mesmo usuário e senha. Peça ao administrador para definir um usuário de acesso exclusivo para cada conta.',csrf_token=csrf_token())
            user=matches[0] if matches else None
            if user:
                if not int(user['ativo'] or 0):
                    register_login_failure(lock_key)
                    return render_template('login.html',erro='Este usuário está bloqueado.',csrf_token=csrf_token())
                if user['role']!='platform_admin':
                    hotel=conn.execute('SELECT id,nome,bloqueado FROM hoteis WHERE id=?',(user['hotel_id'],)).fetchone() if user['hotel_id'] else None
                    if not hotel:
                        return render_template('login.html',erro='Hotel deste usuário não foi encontrado.',csrf_token=csrf_token())
                    if int(hotel['bloqueado'] or 0):
                        return render_template('login.html',erro='O acesso deste hotel está suspenso pelo administrador do SaaS.',csrf_token=csrf_token())
                clear_login_failures(lock_key)
                if isinstance(user['password'],str) and user['password'].startswith('SAASPBKDF2$'):
                    conn.execute('UPDATE usuarios SET password=? WHERE id=?',(generate_password_hash(password,method='pbkdf2:sha256'),user['id']))
                conn.execute('UPDATE usuarios SET ultimo_login=? WHERE id=?',(utc_now_iso(),user['id']))
                conn.commit()
                session.clear(); session.permanent=True
                session['user_id']=user['id']; session['user']=user['username']; session['role']=user['role']; session['hotel_id']=user['hotel_id']
                csrf_token()
                return redirect(url_for('dashboard'))
            register_login_failure(lock_key)
            return render_template('login.html',erro='Usuário ou senha inválidos.',csrf_token=csrf_token())
        finally:
            conn.close()
    return render_template('login.html',csrf_token=csrf_token())

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        hotel_nome = request.form.get('hotel_nome', '').strip()
        servicos_extras = request.form.get('servicos_extras', 'sim').strip().lower() == 'sim'
        possui_estoque = request.form.get('possui_estoque', 'sim').strip().lower() == 'sim'
        # Credenciais de integração ficam no ambiente do servidor, nunca no cadastro do hotel.
        maps_api_status = 'nao_tenho'
        maps_api_key = None

        if not check_csrf():
            return render_template('registro.html', erro='Sessão expirada. Recarregue a página.', csrf_token=csrf_token())
        senha_erro = validate_password(password)
        if senha_erro:
            return render_template('registro.html', erro=senha_erro, csrf_token=csrf_token())

        if not username or not password or not hotel_nome:
            return render_template('registro.html', erro='Preencha todos os campos obrigatórios.', csrf_token=csrf_token())

        faixas_registro=[]
        nomes_faixa=request.form.getlist('faixa_nome[]')
        mins_faixa=request.form.getlist('faixa_min[]')
        maxs_faixa=request.form.getlist('faixa_max[]')
        adicionais_faixa=request.form.getlist('faixa_adicional[]')
        try:
            for i,nome_faixa in enumerate(nomes_faixa):
                nome_faixa=nome_faixa.strip()[:100]
                minimo_raw=mins_faixa[i] if i<len(mins_faixa) else ''
                maximo_raw=maxs_faixa[i] if i<len(maxs_faixa) else ''
                adicional_raw=adicionais_faixa[i] if i<len(adicionais_faixa) else ''
                if not nome_faixa and not minimo_raw and not maximo_raw and not adicional_raw:
                    continue
                minimo=int(minimo_raw);maximo=int(maximo_raw);adicional=float(adicional_raw.replace(',','.'))
                if not nome_faixa or minimo<0 or maximo<minimo or maximo>120 or adicional<0:
                    raise ValueError
                faixas_registro.append((nome_faixa,minimo,maximo,adicional))
        except (ValueError,TypeError):
            return render_template('registro.html', erro='Revise as faixas etárias: nome, idades entre 0 e 120 e adicional não negativo.', csrf_token=csrf_token())
        faixas_registro.sort(key=lambda item:item[1])
        if not faixas_registro or faixas_registro[0][1]!=0 or faixas_registro[-1][2]!=120 or any(faixas_registro[i][1]<=faixas_registro[i-1][2] for i in range(1,len(faixas_registro))) or any(faixas_registro[i][1]!=faixas_registro[i-1][2]+1 for i in range(1,len(faixas_registro))):
            return render_template('registro.html', erro='As faixas devem cobrir dos 0 aos 120 anos, sem sobreposição nem lacunas.', csrf_token=csrf_token())

        conn = get_db()
        cursor = conn.cursor()
        try:
            if cursor.execute('SELECT id FROM usuarios WHERE LOWER(username)=LOWER(?) LIMIT 1',(username,)).fetchone():
                return render_template('registro.html',erro='Este usuário já existe. Escolha um nome de acesso exclusivo.',csrf_token=csrf_token())
            data_cadastro = saas_local_now().date().isoformat()
            cursor.execute('''
                INSERT INTO hoteis
                (nome, data_cadastro, local, servicos_extras, possui_estoque, maps_api_status, maps_api_key)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (hotel_nome, data_cadastro, 'Não informado', int(servicos_extras), int(possui_estoque), maps_api_status, maps_api_key))
            hotel_id = cursor.lastrowid

            cursor.executemany('INSERT INTO faixas_etarias (nome,idade_min,idade_max,valor_adicional,hotel_id) VALUES (?,?,?,?,?)',[(nome,minimo,maximo,adicional,hotel_id) for nome,minimo,maximo,adicional in faixas_registro])

            hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
            cursor.execute('''
                INSERT INTO usuarios (username, nome, password, role, hotel_id, ativo)
                VALUES (?, ?, ?, 'admin', ?, 1)
            ''', (username, username, hashed_pw, hotel_id))

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
                except (ValueError, TypeError, IndexError):
                    continue
                if qtd_t <= 0 or preco_t < 0:
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

            # Cada novo hotel recebe os recursos básicos do SaaS.
            # A preferência escolhida no cadastro fica registrada para a interface.
            ensure_subscription_for_hotel(cursor, hotel_id)
            ensure_servicos_padrao(cursor, hotel_id)
            cursor.execute('DELETE FROM servicos WHERE hotel_id=? AND nome=?', (hotel_id, '__DISABLED_DEFAULT_SERVICES__'))
            conn.commit()
            return render_template('login.html',
                sucesso='Hotel e usuário cadastrados com sucesso! Faça seu login.',
                csrf_token=csrf_token()
            )
        except Exception:
            app.logger.exception('Falha no cadastro de hotel')
            conn.rollback()
            return render_template('registro.html',
                erro='Não foi possível concluir o cadastro. Verifique os dados e tente novamente.',
                csrf_token=csrf_token()
            )
        finally:
            conn.close()

    return render_template('registro.html', csrf_token=csrf_token())

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
            hotel=conn.execute('SELECT id,nome,local,bloqueado,bloqueio_motivo,servicos_extras,possui_estoque,maps_api_status FROM hoteis WHERE id=?',(user['hotel_id'],)).fetchone()
            assinatura=get_subscription(conn,user['hotel_id'])
            if not hotel or int(hotel['bloqueado'] or 0):
                session.clear()
                return render_template('login.html',erro='O acesso deste hotel está suspenso.',csrf_token=csrf_token())
            if user['role']!='platform_admin' and (not assinatura or not assinatura['ativo']):
                return render_template('login.html',erro='A assinatura deste hotel está inativa ou expirada.',csrf_token=csrf_token())
        contexto={'id':user['id'],'username':user['username'],'nome':user['nome'] or user['username'],'role':user['role'],
                  'role_label':ROLE_LABELS.get(user['role'],user['role']),'hotel_id':user['hotel_id'],
                  'hotel_nome':hotel['nome'] if hotel else None,'hotel_local':hotel['local'] if hotel else None,
                  'servicos_extras':bool(hotel['servicos_extras']) if hotel else True,
                  'possui_estoque':bool(hotel['possui_estoque']) if hotel else True,
                  'maps_api_status':hotel['maps_api_status'] if hotel else 'nao_tenho',
                  'assinatura':assinatura}
        menu_items=[
            {'id':'painel','icone':'PD','nome':'Painel','permissao':'reports.view'},
            {'id':'quartos','icone':'QT','nome':'Quartos','permissao':'rooms.view'},
            {'id':'categorias','icone':'CP','nome':'Categorias de pessoas','permissao':'categories.view'},
            {'id':'reservas','icone':'RS','nome':'Reservas','permissao':'reservations.view'},
            {'id':'servicos','icone':'SV','nome':'Serviços e pedidos','permissao':'services.view'},
            {'id':'ordens','icone':'OS','nome':'Ordens de serviço','permissao':'orders.view'},
            {'id':'equipe','icone':'EQ','nome':'Equipe e acessos','permissao':'team.view'},
            {'id':'estoque','icone':'ET','nome':'Estoque','permissao':'stock.view'},
            {'id':'financeiro','icone':'FN','nome':'Financeiro','permissao':'finance.view'},
            {'id':'relatorios','icone':'RL','nome':'Relatórios','permissao':'reports.view'},
            {'id':'integracoes','icone':'IN','nome':'Integrações','permissao':'integrations.view'},
            {'id':'whatsapp','icone':'WA','nome':'WhatsApp','permissao':'whatsapp.use'},
            {'id':'suporte','icone':'?','nome':'Suporte','permissao':'support.view'}]
        if user['role']=='platform_admin':
            menu_items=[{'id':'plataforma','icone':'SA','nome':'Administração SaaS','permissao':'platform'}]
        else:
            menu_items=[item for item in menu_items if can(user['role'],item['permissao'])
                        and not (item['id']=='estoque' and not contexto['possui_estoque'])
                        and not (item['id']=='servicos' and not contexto['servicos_extras'])]
        return render_template('dashboard.html',csrf_token=csrf_token(),contexto_usuario=contexto,menu_inicial=menu_items)
    finally:
        conn.close()

def sincronizar_status_quartos(conn, hotel_id):
    if not hotel_id: return
    hoje=saas_local_now().date().isoformat()
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
    hoje=saas_local_now().date().isoformat()
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
                ('ENTRADA',f"Reserva do quarto {r['quarto_numero']} - {r['check_in']} a {r['check_out']}",float(r['valor_total'] or 0),'Hospedagem',saas_local_now().date().isoformat(),g.hotel_id,'RESERVA',r['id'],forma_pagamento,g.current_user_id))
    fid=cur.lastrowid
    conn.execute("UPDATE reservas SET financeiro_id=?,pago_em=?,pago_por=?,status_pagamento='PAGO' WHERE id=? AND hotel_id=?",(fid,utc_now_iso(),g.current_user_id,reserva_id,g.hotel_id))
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
        reserva=conn.execute("SELECT id FROM reservas WHERE hotel_id=? AND quarto_numero=? AND status<>'CANCELADA' AND check_out>? LIMIT 1",(g.hotel_id,q['numero'],saas_local_now().date().isoformat())).fetchone()
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
        hospede_id=int(data.get('hospede_id')) if data.get('hospede_id') not in (None,'') else None
        quarto_numero=str(data.get('quarto_numero') or '').strip(); check_in=str(data.get('check_in') or ''); check_out=str(data.get('check_out') or '')
        data_in=datetime.date.fromisoformat(check_in); data_out=datetime.date.fromisoformat(check_out)
    except (TypeError,ValueError): return jsonify({'erro':'Informe hóspede, quarto e datas válidas.'}),400
    if data_out<=data_in: return jsonify({'erro':'O check-out deve ser posterior ao check-in.'}),400
    diarias=(data_out-data_in).days
    conn=get_db()
    try:
        novo_hospede=data.get('novo_hospede')
        if isinstance(novo_hospede,dict):
            nome_novo=str(novo_hospede.get('nome') or '').strip()[:180]
            if not nome_novo: return jsonify({'erro':'Informe o nome do novo hóspede.'}),400
            cur=conn.cursor()
            cur.execute('INSERT INTO hospedes (nome,documento,telefone,email,observacoes,hotel_id) VALUES (?,?,?,?,?,?)',
                (nome_novo,str(novo_hospede.get('documento') or '').strip()[:40] or None,str(novo_hospede.get('telefone') or '').strip()[:30] or None,str(novo_hospede.get('email') or '').strip()[:160] or None,None,g.hotel_id))
            hospede_id=cur.lastrowid
        if not hospede_id: return jsonify({'erro':'Selecione um hóspede ou informe os dados do novo hóspede.'}),400
        if not conn.execute('SELECT id FROM hospedes WHERE id=? AND hotel_id=?',(hospede_id,g.hotel_id)).fetchone(): return jsonify({'erro':'Hóspede não pertence ao hotel.'}),403
        q=conn.execute('SELECT * FROM quartos WHERE numero=? AND hotel_id=?',(quarto_numero,g.hotel_id)).fetchone()
        if not q: return jsonify({'erro':'Quarto não encontrado.'}),404
        if reserva_conflito(conn,g.hotel_id,quarto_numero,check_in,check_out): return jsonify({'erro':'Já existe uma reserva para este quarto no período informado.'}),409
        extra,det=composicao_reserva(conn,g.hotel_id,data.get('composicao',[]))
        total=round((float(q['preco_diaria'])+extra)*diarias,2)
        cur=conn.cursor()
        observacoes=str(data.get('observacoes') or '').strip()[:2000] or None
        canal=str(data.get('canal_origem') or 'Direto').strip()[:40]
        if canal not in ('Direto','WhatsApp','Balcão','Booking.com','Expedia','Airbnb','Outro'): canal='Outro'
        cur.execute('INSERT INTO reservas (hospede_id,quarto_numero,check_in,check_out,detalhes_pessoas,diarias,status,valor_total,status_pagamento,hotel_id,criada_por,observacoes,canal_origem) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',
                    (hospede_id,quarto_numero,check_in,check_out,det,diarias,'CONFIRMADA',total,'PENDENTE',g.hotel_id,g.current_user_id,observacoes,canal))
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
        try: hospede_id=int(data.get('hospede_id',r['hospede_id']) or 0) or None; quarto_numero=str(data.get('quarto_numero',r['quarto_numero']) or '').strip(); check_in=str(data.get('check_in',r['check_in'])); check_out=str(data.get('check_out',r['check_out']))
        except (TypeError,ValueError): return jsonify({'erro':'Dados inválidos.'}),400
        novo_hospede=data.get('novo_hospede')
        if isinstance(novo_hospede,dict):
            nome_novo=str(novo_hospede.get('nome') or '').strip()[:180]
            if not nome_novo: return jsonify({'erro':'Informe o nome do novo hóspede.'}),400
            cur=conn.cursor()
            cur.execute('INSERT INTO hospedes (nome,documento,telefone,email,observacoes,hotel_id) VALUES (?,?,?,?,?,?)',
                (nome_novo,str(novo_hospede.get('documento') or '').strip()[:40] or None,str(novo_hospede.get('telefone') or '').strip()[:30] or None,str(novo_hospede.get('email') or '').strip()[:160] or None,None,g.hotel_id))
            hospede_id=cur.lastrowid
        try: diarias=(datetime.date.fromisoformat(check_out)-datetime.date.fromisoformat(check_in)).days
        except ValueError: return jsonify({'erro':'Datas inválidas.'}),400
        if diarias<1: return jsonify({'erro':'O check-out deve ser posterior ao check-in.'}),400
        if not conn.execute('SELECT id FROM hospedes WHERE id=? AND hotel_id=?',(hospede_id,g.hotel_id)).fetchone(): return jsonify({'erro':'Hóspede inválido.'}),403
        q=conn.execute('SELECT * FROM quartos WHERE numero=? AND hotel_id=?',(quarto_numero,g.hotel_id)).fetchone()
        if not q: return jsonify({'erro':'Quarto não encontrado.'}),404
        if reserva_conflito(conn,g.hotel_id,quarto_numero,check_in,check_out,rid): return jsonify({'erro':'Existe outra reserva conflitante para este quarto.'}),409
        extra,det=composicao_reserva(conn,g.hotel_id,data.get('composicao',[]))
        total=round((float(q['preco_diaria'])+extra)*diarias,2)
        observacoes=str(data.get('observacoes',r['observacoes']) or '').strip()[:2000] or None
        canal=str(data.get('canal_origem',r['canal_origem'] or 'Direto') or 'Direto').strip()[:40]
        if canal not in ('Direto','WhatsApp','Balcão','Booking.com','Expedia','Airbnb','Outro'): canal='Outro'
        conn.execute('UPDATE reservas SET hospede_id=?,quarto_numero=?,check_in=?,check_out=?,detalhes_pessoas=?,diarias=?,valor_total=?,observacoes=?,canal_origem=? WHERE id=? AND hotel_id=?',(hospede_id,quarto_numero,check_in,check_out,det,diarias,total,observacoes,canal,rid,g.hotel_id))
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
        conn.execute("UPDATE reservas SET status='CANCELADA',cancelada_em=?,status_pagamento='PENDENTE',financeiro_id=NULL,pago_em=NULL,pago_por=NULL WHERE id=? AND hotel_id=?",(saas_local_now().isoformat(),rid,g.hotel_id))
        sincronizar_status_quartos(conn,g.hotel_id); conn.commit(); return jsonify({'mensagem':'Reserva cancelada.'}),200
    finally: conn.close()

@app.route('/api/reservas/<int:rid>/movimentacao',methods=['PUT'])
@token_required
def registrar_movimentacao_reserva(current_user,role,rid):
    data=request.get_json(silent=True) or {}; acao=str(data.get('acao') or '').strip().lower()
    if acao not in ('checkin','checkout'): return jsonify({'erro':'Ação inválida.'}),400
    conn=get_db()
    try:
        reserva=conn.execute('SELECT id,status,checkin_realizado_em,checkout_realizado_em FROM reservas WHERE id=? AND hotel_id=?',(rid,g.hotel_id)).fetchone()
        if not reserva: return jsonify({'erro':'Reserva não encontrada.'}),404
        if reserva['status']=='CANCELADA': return jsonify({'erro':'Não é possível registrar movimentação de reserva cancelada.'}),409
        campo='checkin_realizado_em' if acao=='checkin' else 'checkout_realizado_em'
        if reserva[campo]: return jsonify({'erro':'Esta movimentação já foi registrada.'}),409
        agora=saas_local_now().isoformat()
        conn.execute(f'UPDATE reservas SET {campo}=? WHERE id=? AND hotel_id=?',(agora,rid,g.hotel_id))
        sincronizar_status_quartos(conn,g.hotel_id); conn.commit()
        return jsonify({'mensagem':'Check-in registrado.' if acao=='checkin' else 'Check-out registrado.'}),200
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
            cur=conn.cursor(); cur.execute('INSERT INTO fluxo_caixa (tipo,descricao,valor,categoria,data,hotel_id,origem_tipo,criado_por) VALUES (?,?,?,?,?,?,?,?)',(tipo,desc,valor,cat,str(data.get('data') or saas_local_now().date().isoformat()),g.hotel_id,None,g.current_user_id)); conn.commit()
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

def enviar_notificacao_whatsapp_os(conn, hotel_id, ordem_id):
    """Envia aviso de OS pela WhatsApp Cloud API, sem impedir a criação da ordem."""
    token=os.getenv('WHATSAPP_CLOUD_API_ACCESS_TOKEN','').strip()
    phone_id=os.getenv('WHATSAPP_CLOUD_API_PHONE_NUMBER_ID','').strip()
    version=os.getenv('WHATSAPP_CLOUD_API_VERSION','').strip()
    template_name=os.getenv('WHATSAPP_CLOUD_API_TEMPLATE_NAME','').strip()
    template_language=os.getenv('WHATSAPP_CLOUD_API_TEMPLATE_LANGUAGE','pt_BR').strip() or 'pt_BR'
    if not (token and phone_id and version):
        return {'status':'nao_configurada','mensagem':'WhatsApp Cloud API não configurada no servidor.'}
    row=conn.execute('''SELECT o.*,q.numero AS quarto_numero,q.andar,u.nome AS responsavel_nome,
                               u.telefone,u.whatsapp_notificacoes,sol.nome AS solicitante_nome
                        FROM ordens_servico o
                        LEFT JOIN quartos q ON q.id=o.quarto_id AND q.hotel_id=o.hotel_id
                        LEFT JOIN usuarios u ON u.id=o.responsavel_id AND u.hotel_id=o.hotel_id
                        LEFT JOIN usuarios sol ON sol.id=o.solicitante_id AND sol.hotel_id=o.hotel_id
                        WHERE o.id=? AND o.hotel_id=?''',(ordem_id,hotel_id)).fetchone()
    if not row or not row['responsavel_id']:
        return {'status':'sem_responsavel','mensagem':'Ordem criada sem funcionário atribuído.'}
    if not row['telefone'] or not int(row['whatsapp_notificacoes'] or 0):
        return {'status':'destinatario_nao_configurado','mensagem':'Funcionário sem telefone ou sem autorização para notificações.'}
    destino=''.join(ch for ch in str(row['telefone']) if ch.isdigit())
    if len(destino)<10 or len(destino)>15:
        return {'status':'telefone_invalido','mensagem':'Telefone do funcionário deve incluir DDI e DDD.'}
    andar=f" · {row['andar']}º andar" if row['andar'] is not None else ''
    descricao=str(row['descricao'] or '').strip()
    mensagem=(f"🔧 Nova ordem de serviço #{ordem_id}\n"
              f"Quarto {row['quarto_numero'] or row['quarto']}{andar}\n"
              f"Setor: {row['tipo']}\nResponsável: {row['responsavel_nome'] or 'Equipe'}\n"
              f"Solicitada por: {row['solicitante_nome'] or 'Recepção'}\n"
              f"Prioridade: {row['prioridade']}\nDescrição: {descricao}")
    if template_name:
        parametros=[str(ordem_id),f"{row['quarto_numero'] or row['quarto']}{andar}",str(row['tipo']),str(row['responsavel_nome'] or 'Equipe'),str(row['solicitante_nome'] or 'Recepção'),str(row['prioridade']),descricao]
        conteudo={'messaging_product':'whatsapp','to':destino,'type':'template','template':{'name':template_name,'language':{'code':template_language},'components':[{'type':'body','parameters':[{'type':'text','text':valor} for valor in parametros]}]}}
    else:
        conteudo={'messaging_product':'whatsapp','to':destino,'type':'text','text':{'body':mensagem}}
    payload=json.dumps(conteudo,ensure_ascii=False).encode('utf-8')
    req=urllib.request.Request(f'https://graph.facebook.com/{version}/{phone_id}/messages',data=payload,method='POST',headers={'Authorization':f'Bearer {token}','Content-Type':'application/json'})
    try:
        with urllib.request.urlopen(req,timeout=8) as response:
            if 200<=response.status<300:
                return {'status':'enviada','mensagem':'Aviso enviado por WhatsApp.'}
            return {'status':'falha','mensagem':'WhatsApp não confirmou o envio.'}
    except Exception:
        app.logger.exception('Falha ao enviar notificação de OS pelo WhatsApp')
        return {'status':'falha','mensagem':'Não foi possível enviar o aviso. A ordem foi salva.'}

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
            cur=conn.cursor(); now=utc_now_iso()
            cur.execute('INSERT INTO ordens_servico (quarto,tipo,descricao,status,hotel_id,quarto_id,hospede_id,solicitante_id,responsavel_id,prioridade,aberta_em) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                        (q['numero'],tipo,desc,'PENDENTE',g.hotel_id,quarto_id,hospede_id,g.current_user_id,responsavel_id,prioridade,now))
            oid=cur.lastrowid; conn.commit()
            notificacao=enviar_notificacao_whatsapp_os(conn,g.hotel_id,oid)
            return jsonify({'mensagem':'Ordem de serviço criada.','id':oid,'notificacao_whatsapp':notificacao}),201
        rows=conn.execute('''
            SELECT o.*,h.nome AS hospede_nome,u.nome AS responsavel_nome,u.telefone AS responsavel_telefone,
                   sol.nome AS solicitante_nome,q.andar AS quarto_andar
            FROM ordens_servico o
            LEFT JOIN hospedes h ON h.id=o.hospede_id AND h.hotel_id=o.hotel_id
            LEFT JOIN usuarios u ON u.id=o.responsavel_id AND u.hotel_id=o.hotel_id
            LEFT JOIN usuarios sol ON sol.id=o.solicitante_id AND sol.hotel_id=o.hotel_id
            LEFT JOIN quartos q ON q.id=o.quarto_id AND q.hotel_id=o.hotel_id
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
        concluida=utc_now_iso() if status=='CONCLUIDA' else None
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
        hoje=saas_local_now().date(); hoje_s=hoje.isoformat()
        try:
            inicio=datetime.date.fromisoformat(request.args.get('inicio') or hoje_s)
            fim=datetime.date.fromisoformat(request.args.get('fim') or hoje_s)
        except ValueError:
            return jsonify({'erro':'Informe datas válidas no formato AAAA-MM-DD.'}),400
        if fim<inicio: return jsonify({'erro':'A data final deve ser igual ou posterior à inicial.'}),400
        dias_periodo=(fim-inicio).days+1
        if dias_periodo>366: return jsonify({'erro':'O período máximo do relatório é de 366 dias.'}),400
        total=int(conn.execute('SELECT COUNT(*) AS t FROM quartos WHERE hotel_id=?',(g.hotel_id,)).fetchone()['t'] or 0)

        def carregar_periodo(dt_ini,dt_fim):
            dt_fim_exclusivo=dt_fim+datetime.timedelta(days=1)
            reservas=conn.execute('''SELECT r.*,q.tipo AS categoria_quarto FROM reservas r
                LEFT JOIN quartos q ON q.numero=r.quarto_numero AND q.hotel_id=r.hotel_id
                WHERE r.hotel_id=? AND r.status<>'CANCELADA' AND r.check_in<? AND r.check_out>?''',
                (g.hotel_id,dt_fim_exclusivo.isoformat(),dt_ini.isoformat())).fetchall()
            quartos_por_dia={}; receita_gerada=0.0; receita_pendente=0.0; noites=0; por_categoria={}; pessoas_reservadas=0
            for reserva in reservas:
                try: entrada=datetime.date.fromisoformat(str(reserva['check_in'])[:10]); saida=datetime.date.fromisoformat(str(reserva['check_out'])[:10])
                except (TypeError,ValueError): continue
                noites_reserva=max((saida-entrada).days,1); diaria=float(reserva['valor_total'] or 0)/noites_reserva
                primeiro=max(entrada,dt_ini); ultimo=min(saida,dt_fim_exclusivo)
                quantidade_noites=max((ultimo-primeiro).days,0)
                if not quantidade_noites: continue
                valor_periodo=diaria*quantidade_noites; receita_gerada+=valor_periodo; noites+=quantidade_noites
                if str(reserva['status_pagamento'] or '').upper()!='PAGO': receita_pendente+=valor_periodo
                categoria=str(reserva['categoria_quarto'] or 'Sem categoria')
                grupo=por_categoria.setdefault(categoria,{'receita':0.0,'diarias':0})
                grupo['receita']+=valor_periodo; grupo['diarias']+=quantidade_noites
                pessoas=re.findall(r'(\d+)\s*x',str(reserva['detalhes_pessoas'] or ''),flags=re.IGNORECASE)
                pessoas_reservadas+=sum(int(x) for x in pessoas) if pessoas else 1
                dia=primeiro
                while dia<ultimo:
                    quartos_por_dia[dia.isoformat()]=quartos_por_dia.get(dia.isoformat(),0)+1
                    dia+=datetime.timedelta(days=1)
            serie=[]; ocupacao_soma=0.0; capacidade=total*dias_periodo
            dia=dt_ini
            while dia<=dt_fim:
                ocupados=quartos_por_dia.get(dia.isoformat(),0); percentual=(ocupados/total*100) if total else 0
                serie.append({'data':dia.isoformat(),'quartos_ocupados':ocupados,'ocupacao':round(percentual,2)})
                ocupacao_soma+=percentual; dia+=datetime.timedelta(days=1)
            ocupacao_media=ocupacao_soma/dias_periodo if dias_periodo else 0
            adr=receita_gerada/noites if noites else 0
            revpar=receita_gerada/capacidade if capacidade else 0
            categorias=[{'categoria':k,'receita':round(v['receita'],2),'diarias':v['diarias'],'adr':round(v['receita']/v['diarias'],2) if v['diarias'] else 0} for k,v in sorted(por_categoria.items())]
            return reservas,serie,receita_gerada,receita_pendente,noites,ocupacao_media,adr,revpar,categorias,pessoas_reservadas

        reservas,serie,gerada,pendente,noites,ocupacao,adr,revpar,categorias,pessoas_periodo=carregar_periodo(inicio,fim)
        receita_caixa=float(conn.execute("SELECT COALESCE(SUM(valor),0) AS s FROM fluxo_caixa WHERE hotel_id=? AND tipo='ENTRADA' AND data>=? AND data<=?",(g.hotel_id,inicio.isoformat(),fim.isoformat())).fetchone()['s'] or 0)
        receita_servicos=float(conn.execute("SELECT COALESCE(SUM(quantidade*preco_unitario),0) AS s FROM pedidos_hospede WHERE hotel_id=? AND status_pagamento='PAGO' AND substr(COALESCE(pago_em,solicitado_em),1,10)>=? AND substr(COALESCE(pago_em,solicitado_em),1,10)<=?",(g.hotel_id,inicio.isoformat(),fim.isoformat())).fetchone()['s'] or 0)
        cancelamentos=int(conn.execute("SELECT COUNT(*) AS n FROM reservas WHERE hotel_id=? AND status='CANCELADA' AND COALESCE(substr(cancelada_em,1,10),check_in)>=? AND COALESCE(substr(cancelada_em,1,10),check_in)<=?",(g.hotel_id,inicio.isoformat(),fim.isoformat())).fetchone()['n'] or 0)
        hoje_reservas=conn.execute("SELECT COUNT(*) AS n FROM reservas WHERE hotel_id=? AND status<>'CANCELADA' AND check_in=?",(g.hotel_id,hoje_s)).fetchone()['n'] or 0
        sem_checkin=int(conn.execute("SELECT COUNT(*) AS n FROM reservas WHERE hotel_id=? AND status<>'CANCELADA' AND check_in=? AND checkin_realizado_em IS NULL",(g.hotel_id,hoje_s)).fetchone()['n'] or 0)
        entradas_realizadas=int(conn.execute("SELECT COUNT(*) AS n FROM reservas WHERE hotel_id=? AND status<>'CANCELADA' AND substr(checkin_realizado_em,1,10)=?",(g.hotel_id,hoje_s)).fetchone()['n'] or 0)
        saidas_previstas=int(conn.execute("SELECT COUNT(*) AS n FROM reservas WHERE hotel_id=? AND status<>'CANCELADA' AND check_out=?",(g.hotel_id,hoje_s)).fetchone()['n'] or 0)
        saidas_realizadas=int(conn.execute("SELECT COUNT(*) AS n FROM reservas WHERE hotel_id=? AND status<>'CANCELADA' AND substr(checkout_realizado_em,1,10)=?",(g.hotel_id,hoje_s)).fetchone()['n'] or 0)
        em_casa=conn.execute("SELECT detalhes_pessoas FROM reservas WHERE hotel_id=? AND status<>'CANCELADA' AND checkin_realizado_em IS NOT NULL AND checkout_realizado_em IS NULL AND check_in<=? AND check_out>?",(g.hotel_id,hoje_s,hoje_s)).fetchall()
        hospedes_inhouse=sum((sum(int(x) for x in re.findall(r'(\d+)\s*x',str(r['detalhes_pessoas'] or ''),flags=re.IGNORECASE)) or 1) for r in em_casa)
        canais=conn.execute("SELECT COALESCE(NULLIF(canal_origem,''),'Direto') AS canal,COUNT(*) AS total FROM reservas WHERE hotel_id=? AND status<>'CANCELADA' AND check_in>=? AND check_in<=? GROUP BY COALESCE(NULLIF(canal_origem,''),'Direto') ORDER BY total DESC",(g.hotel_id,inicio.isoformat(),fim.isoformat())).fetchall()
        dias_prev=[]
        for offset in range(1,8):
            data_prev=hoje+datetime.timedelta(days=offset); limite=conn.execute("SELECT COUNT(*) AS n FROM reservas WHERE hotel_id=? AND status<>'CANCELADA' AND checkout_realizado_em IS NULL AND check_in<=? AND check_out>?",(g.hotel_id,data_prev.isoformat(),data_prev.isoformat())).fetchone()['n'] or 0
            dias_prev.append({'data':data_prev.isoformat(),'quartos':int(limite),'ocupacao':round((int(limite)/total*100),2) if total else 0})
        dias_antes=dias_periodo
        fim_anterior=inicio-datetime.timedelta(days=1); inicio_anterior=fim_anterior-datetime.timedelta(days=dias_antes-1)
        _,_,_,_,_,ocupacao_anterior,_,_,_,_=carregar_periodo(inicio_anterior,fim_anterior)
        caixa_anterior=float(conn.execute("SELECT COALESCE(SUM(valor),0) AS s FROM fluxo_caixa WHERE hotel_id=? AND tipo='ENTRADA' AND data>=? AND data<=?",(g.hotel_id,inicio_anterior.isoformat(),fim_anterior.isoformat())).fetchone()['s'] or 0)
        ticket_extra=receita_servicos/pessoas_periodo if pessoas_periodo else 0
        return jsonify({'inicio':inicio.isoformat(),'fim':fim.isoformat(),'dias':dias_periodo,'total_quartos':total,
            'quartos_ocupados':serie[-1]['quartos_ocupados'] if serie else 0,'taxa_ocupacao':round(ocupacao,2),
            'receita_total':round(receita_caixa,2),'receita_hospedagem':round(gerada,2),'receita_gerada':round(gerada,2),
            'receita_a_vencer':round(pendente,2),'receita_servicos':round(receita_servicos,2),'adr':round(adr,2),'revpar':round(revpar,2),
            'cancelamentos':cancelamentos,'no_show':sem_checkin,'no_show_percentual':round(sem_checkin/hoje_reservas*100,2) if hoje_reservas else 0,
            'checkins_previstos':int(hoje_reservas),'checkins_realizados':entradas_realizadas,'checkouts_previstos':int(saidas_previstas),
            'checkouts_realizados':saidas_realizadas,'hospedes_inhouse':hospedes_inhouse,'ticket_medio_hospede':round(ticket_extra,2),
            'ocupacao_serie':serie,'previsao_ocupacao':dias_prev,'adr_categoria':categorias,'origem_reservas':[dict(x) for x in canais],
            'comparativo':{'ocupacao_anterior':round(ocupacao_anterior,2),'receita_anterior':round(caixa_anterior,2),
                'variacao_ocupacao':round(ocupacao-ocupacao_anterior,2),
                'variacao_receita_percentual':round((receita_caixa-caixa_anterior)/abs(caixa_anterior)*100,2) if caixa_anterior else (100.0 if receita_caixa else 0.0)}}),200
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
        rows=conn.execute('SELECT id,username,nome,role,email,ativo,ultimo_login,telefone,whatsapp_notificacoes FROM usuarios WHERE hotel_id=? ORDER BY ativo DESC,nome,username',(g.hotel_id,)).fetchall()
        return jsonify([dict(x,role_label=ROLE_LABELS.get(x['role'],x['role'])) for x in rows]),200
    finally: conn.close()

@app.route('/api/usuarios',methods=['POST'])
@token_required
def criar_usuario_hotel(current_user,role):
    if not hotel_admin_only(role): return jsonify({'erro':'Apenas o administrador do hotel pode adicionar perfis.'}),403
    data=request.get_json(silent=True) or {}
    username=str(data.get('username') or '').strip()[:80]; nome=str(data.get('nome') or username).strip()[:160]
    email=str(data.get('email') or '').strip()[:160] or None; senha=str(data.get('password') or '')
    telefone=str(data.get('telefone') or '').strip()[:40] or None; wa_optin=1 if data.get('whatsapp_notificacoes') else 0
    digitos_telefone=''.join(ch for ch in (telefone or '') if ch.isdigit())
    if wa_optin and not 10<=len(digitos_telefone)<=15: return jsonify({'erro':'Informe o telefone com DDI e DDD para ativar avisos por WhatsApp.'}),400
    perfil=str(data.get('role') or 'recepcao').strip()
    if perfil not in ROLE_LABELS or perfil=='platform_admin': return jsonify({'erro':'Perfil inválido.'}),400
    if not username or not senha: return jsonify({'erro':'Usuário e senha são obrigatórios.'}),400
    erro=validate_password(senha)
    if erro: return jsonify({'erro':erro}),400
    conn=get_db()
    try:
        if conn.execute('SELECT id FROM usuarios WHERE LOWER(username)=LOWER(?)',(username,)).fetchone(): return jsonify({'erro':'Este usuário já está em uso. Escolha um nome de acesso exclusivo.'}),409
        ok,mensagem=enforce_user_quota(conn,1)
        if not ok: return jsonify({'erro':mensagem}),403
        cur=conn.cursor()
        cur.execute('INSERT INTO usuarios (username,nome,password,role,hotel_id,email,ativo,telefone,whatsapp_notificacoes) VALUES (?,?,?,?,?,?,1,?,?)',
                    (username,nome,generate_password_hash(senha,method='pbkdf2:sha256'),perfil,g.hotel_id,email,telefone,wa_optin))
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
        telefone=str(data.get('telefone',u['telefone'] or '') or '').strip()[:40] or None
        wa_optin=1 if bool(data.get('whatsapp_notificacoes',u['whatsapp_notificacoes'] or 0)) else 0
        digitos_telefone=''.join(ch for ch in (telefone or '') if ch.isdigit())
        if wa_optin and not 10<=len(digitos_telefone)<=15: return jsonify({'erro':'Informe o telefone com DDI e DDD para ativar avisos por WhatsApp.'}),400
        perfil=str(data.get('role',u['role']) or u['role'])
        ativo=1 if bool(data.get('ativo',u['ativo'])) else 0
        if perfil not in ROLE_LABELS or perfil=='platform_admin': return jsonify({'erro':'Perfil inválido.'}),400
        if uid==g.current_user_id and not ativo: return jsonify({'erro':'O administrador atual não pode se bloquear por esta tela.'}),409
        if uid==g.current_user_id and perfil!='admin': return jsonify({'erro':'O administrador principal não pode remover o próprio perfil de administrador.'}),409
        if u['role']=='admin' and (not ativo or perfil!='admin'):
            outros=conn.execute("SELECT COUNT(*) AS total FROM usuarios WHERE hotel_id=? AND role='admin' AND ativo=1 AND id<>?",(g.hotel_id,uid)).fetchone()['total']
            if int(outros)==0: return jsonify({'erro':'O hotel precisa manter pelo menos um administrador ativo.'}),409
        campos=['nome=?','email=?','role=?','ativo=?','telefone=?','whatsapp_notificacoes=?']; params=[novo_nome,email,perfil,ativo,telefone,wa_optin]
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
                                    ('ENTRADA',f"Pedido do hóspede - {p['item']} - quarto {p['quarto_id'] or ''}",total,'Serviços',saas_local_now().date().isoformat(),g.hotel_id,'PEDIDO',p['id'],forma_pagamento,g.current_user_id))
    fid=cur.lastrowid
    conn.execute("UPDATE pedidos_hospede SET status_pagamento='PAGO',pago_em=?,pago_por=?,financeiro_id=? WHERE id=? AND hotel_id=?",(utc_now_iso(),g.current_user_id,fid,pedido_id,g.hotel_id))
    return fid

@app.route('/api/pedidos',methods=['GET','POST'])
@token_required
def listar_pedidos(current_user,role):
    conn=get_db()
    try:
        if request.method=='POST':
            if not can(role,'requests.manage'):
                return jsonify({'erro':'Seu perfil não pode criar pedidos.'}),403
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
                except (TypeError,ValueError): return jsonify({'erro':'Reserva inválida.'}),400
                reserva=conn.execute('SELECT id,quarto_numero,hospede_id FROM reservas WHERE id=? AND hotel_id=?',(reserva_id,g.hotel_id)).fetchone()
                if not reserva: return jsonify({'erro':'Reserva inválida.'}),400
                if str(reserva['quarto_numero'])!=str(q['numero']): return jsonify({'erro':'O quarto selecionado não corresponde à reserva.'}),400
                if hospede_id and reserva['hospede_id'] and int(hospede_id)!=int(reserva['hospede_id']): return jsonify({'erro':'O hóspede selecionado não corresponde à reserva.'}),400
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
                (g.hotel_id,reserva_id,quarto_id,hospede_id,servico_id,item,descricao,quantidade,preco,'ABERTO','PENDENTE',utc_now_iso(),g.current_user_id))
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

@app.route('/api/pedidos/<int:pid>',methods=['PUT'])
@token_required
def editar_pedido(current_user,role,pid):
    data=request.get_json(silent=True) or {}; conn=get_db()
    try:
        p=conn.execute('SELECT * FROM pedidos_hospede WHERE id=? AND hotel_id=?',(pid,g.hotel_id)).fetchone()
        if not p: return jsonify({'erro':'Pedido não encontrado.'}),404
        if p['status_pagamento']=='PAGO': return jsonify({'erro':'Pedido já pago não pode ser editado. Marque como não pago antes de corrigir.'}),409
        try: quarto_id=int(data.get('quarto_id',p['quarto_id']))
        except (TypeError,ValueError): return jsonify({'erro':'Quarto inválido.'}),400
        if not conn.execute('SELECT id FROM quartos WHERE id=? AND hotel_id=?',(quarto_id,g.hotel_id)).fetchone(): return jsonify({'erro':'Quarto inválido.'}),400
        hospede_id=data.get('hospede_id',p['hospede_id'])
        if hospede_id not in (None,''):
            try: hospede_id=int(hospede_id)
            except (TypeError,ValueError): return jsonify({'erro':'Hóspede inválido.'}),400
            if not conn.execute('SELECT id FROM hospedes WHERE id=? AND hotel_id=?',(hospede_id,g.hotel_id)).fetchone(): return jsonify({'erro':'Hóspede inválido.'}),400
        servico_id=data.get('servico_id',p['servico_id'])
        service=None
        if servico_id not in (None,''):
            try: servico_id=int(servico_id)
            except (TypeError,ValueError): return jsonify({'erro':'Serviço inválido.'}),400
            service=conn.execute('SELECT * FROM servicos WHERE id=? AND hotel_id=?',(servico_id,g.hotel_id)).fetchone()
            if not service: return jsonify({'erro':'Serviço não encontrado.'}),404
        item=str(data.get('item',p['item']) or (service['nome'] if service else '')).strip()[:120]
        desc=str(data.get('descricao',p['descricao'] or '') or '').strip()[:500] or None
        try: qtd=float(data.get('quantidade',p['quantidade'])); preco=float(data.get('preco_unitario',service['preco'] if service else p['preco_unitario']))
        except (TypeError,ValueError): return jsonify({'erro':'Quantidade ou preço inválido.'}),400
        if not item or qtd<=0 or preco<0: return jsonify({'erro':'Revise item, quantidade e preço.'}),400
        conn.execute('UPDATE pedidos_hospede SET quarto_id=?,hospede_id=?,servico_id=?,item=?,descricao=?,quantidade=?,preco_unitario=? WHERE id=? AND hotel_id=?',
                     (quarto_id,hospede_id,servico_id,item,desc,qtd,preco,pid,g.hotel_id))
        conn.commit(); return jsonify({'mensagem':'Pedido atualizado.','total':round(qtd*preco,2)}),200
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
    url_configurada=os.getenv('ASAAS_BASE_URL','').strip().rstrip('/')
    if url_configurada:
        return url_configurada
    if ambiente in ('producao','production','prod'):
        return 'https://api.asaas.com/v3'
    return 'https://api-sandbox.asaas.com/v3'

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
                'nextDueDate':(saas_local_now().date()+datetime.timedelta(days=1)).isoformat()
            }
        }

        agora=utc_now_iso()
        conn.execute('INSERT INTO checkout_assinaturas (hotel_id,plano_id,external_reference,status,criado_em,atualizado_em) VALUES (?,?,?,?,?,?)',
                     (g.hotel_id,plano_id,referencia,'CRIANDO',agora,agora))
        conn.commit()

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
            conn.execute('UPDATE checkout_assinaturas SET status=?,atualizado_em=? WHERE external_reference=?',('ERRO',utc_now_iso(),referencia)); conn.commit()
            return jsonify({'erro':'Não foi possível criar o Checkout Asaas. Verifique ambiente e credenciais.'}),502

        checkout_id=str(body.get('id') or '').strip()
        if not checkout_id:
            conn.execute('UPDATE checkout_assinaturas SET status=?,atualizado_em=? WHERE external_reference=?',('ERRO',utc_now_iso(),referencia)); conn.commit()
            app.logger.error('Asaas criou resposta sem ID de checkout para referência interna %s',referencia)
            return jsonify({'erro':'O Asaas não retornou o identificador do Checkout.'}),502
        checkout_url=body.get('link') or body.get('url') or ('https://asaas.com/checkoutSession/show?id='+urllib.parse.quote(checkout_id))
        conn.execute('UPDATE checkout_assinaturas SET checkout_id=?,status=?,atualizado_em=? WHERE external_reference=?',
                     (checkout_id,'PENDENTE',utc_now_iso(),referencia))
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
        hotel=conn.execute('SELECT whatsapp_telefone FROM hoteis WHERE id=?',(g.hotel_id,)).fetchone()
        integracao['whatsapp_telefone']=hotel['whatsapp_telefone'] if hotel else None
        integracao['whatsapp_api_configurada']=bool(os.getenv('WHATSAPP_CLOUD_API_ACCESS_TOKEN','').strip() and os.getenv('WHATSAPP_CLOUD_API_PHONE_NUMBER_ID','').strip() and os.getenv('WHATSAPP_CLOUD_API_VERSION','').strip())
        integracao['geoapify_api_configurada']=bool(os.getenv('GEOAPIFY_API_KEY','').strip())
        integracao['geoapify_maps_configurada']=bool(os.getenv('GEOAPIFY_MAPS_API_KEY','').strip())
        integracao['asaas_configurada']=bool(os.getenv('ASAAS_API_KEY','').strip() and os.getenv('ASAAS_WEBHOOK_TOKEN','').strip() and os.getenv('SAAS_PUBLIC_URL','').strip())
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
    whatsapp_telefone=''.join(ch for ch in str(data.get('whatsapp_telefone') or '') if ch.isdigit()) or None
    if whatsapp_telefone and not 10<=len(whatsapp_telefone)<=15:
        return jsonify({'erro':'Informe o WhatsApp do hotel com DDI e DDD (10 a 15 dígitos).'}),400
    conn=get_db()
    try:
        now=utc_now_iso()
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
        conn.execute('UPDATE hoteis SET whatsapp_telefone=? WHERE id=?',(whatsapp_telefone,g.hotel_id))
        conn.commit()
        return jsonify({'mensagem':'Integrações salvas com sucesso.','integracao':get_hotel_integracoes(conn,g.hotel_id)}),200
    finally:
        conn.close()

@app.route('/api/integracoes/maps/pesquisar', methods=['POST'])
@token_required
def pesquisar_maps(current_user, role):
    api_key=os.getenv('GEOAPIFY_API_KEY','').strip()
    if not api_key:
        return jsonify({'erro':'Configure GEOAPIFY_API_KEY no arquivo .env do servidor.'}),503
    data=request.get_json(silent=True) or {}
    consulta=str(data.get('q') or '').strip()
    if len(consulta)<3 or len(consulta)>300:
        return jsonify({'erro':'Informe o nome ou endereço do hotel (3 a 300 caracteres).'}),400
    params=urllib.parse.urlencode({'text':consulta,'lang':'pt','limit':5,'format':'json','apiKey':api_key})
    req=urllib.request.Request('https://api.geoapify.com/v1/geocode/search?'+params,method='GET')
    try:
        with urllib.request.urlopen(req,timeout=10) as response:
            raw=json.loads(response.read().decode('utf-8'))
    except Exception:
        return jsonify({'erro':'Não foi possível consultar Geoapify agora. Verifique a chave e o limite do plano.'}),502
    resultados=[]
    for p in raw.get('results',[]):
        lat,lon=p.get('lat'),p.get('lon')
        nome=p.get('name') or p.get('address_line1') or p.get('formatted')
        maps_url=(f'https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=16/{lat}/{lon}'
                  if lat is not None and lon is not None else None)
        resultados.append({'id':p.get('place_id'),'nome':nome,
                           'endereco':p.get('formatted'),'latitude':lat,
                           'longitude':lon,'maps_url':maps_url})
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
    now=utc_now_iso()

    payment=data.get('payment') if isinstance(data.get('payment'),dict) else {}
    checkout=data.get('checkout') if isinstance(data.get('checkout'),dict) else {}
    subscription=data.get('subscription') if isinstance(data.get('subscription'),dict) else {}
    external_subscription=payment.get('subscription') or subscription.get('id')
    if isinstance(external_subscription,dict):
        external_subscription=external_subscription.get('id')
    external_reference=(payment.get('externalReference') or checkout.get('externalReference') or
                        subscription.get('externalReference') or data.get('externalReference'))
    checkout_id=checkout.get('id') or data.get('checkoutId')

    conn=get_db()
    try:
        existente=conn.execute('SELECT id,status FROM webhook_eventos WHERE provider=? AND event_id=?',('asaas',event_id)).fetchone()
        if existente:
            return jsonify({'ok':True,'duplicado':True,'status':existente['status']}),200

        pedido_checkout=None
        if external_reference or checkout_id or external_subscription:
            pedido_checkout=conn.execute('''
                SELECT * FROM checkout_assinaturas
                WHERE (? IS NOT NULL AND external_reference=?)
                   OR (? IS NOT NULL AND checkout_id=?)
                   OR (? IS NOT NULL AND asaas_subscription_id=?)
                ORDER BY id DESC LIMIT 1
            ''',(str(external_reference) if external_reference else None,str(external_reference) if external_reference else None,
                 str(checkout_id) if checkout_id else None,str(checkout_id) if checkout_id else None,
                 str(external_subscription) if external_subscription else None,str(external_subscription) if external_subscription else None)).fetchone()

        hotel_id=pedido_checkout['hotel_id'] if pedido_checkout else None
        conn.execute('INSERT INTO webhook_eventos (provider,event_id,event_type,hotel_id,payload,recebido_em,status) VALUES (?,?,?,?,?,?,?)',
                     ('asaas',event_id,event_type,hotel_id,payload,now,'RECEBIDO'))

        if not pedido_checkout:
            status_evento='SEM_VINCULO'
        else:
            local_id=pedido_checkout['id']
            if external_subscription:
                conn.execute('UPDATE checkout_assinaturas SET asaas_subscription_id=?,atualizado_em=? WHERE id=?',
                             (str(external_subscription),now,local_id))

            if event_type in ('CHECKOUT_CANCELED','CHECKOUT_EXPIRED'):
                status_evento='CANCELADO' if event_type=='CHECKOUT_CANCELED' else 'EXPIRADO'
                conn.execute('UPDATE checkout_assinaturas SET status=?,atualizado_em=? WHERE id=?',(status_evento,now,local_id))
            elif event_type in ('SUBSCRIPTION_INACTIVATED','SUBSCRIPTION_DELETED'):
                subscription_id=str(external_subscription or pedido_checkout['asaas_subscription_id'] or '')
                if subscription_id:
                    conn.execute('UPDATE assinaturas SET status=?,atualizado_em=? WHERE hotel_id=? AND assinatura_externa=?',
                                 ('CANCELADA',now,hotel_id,subscription_id))
                conn.execute('UPDATE checkout_assinaturas SET status=?,atualizado_em=? WHERE id=?',('CANCELADA',now,local_id))
                status_evento='PROCESSADO'
            elif event_type in ('PAYMENT_OVERDUE','PAYMENT_DELETED','PAYMENT_REFUNDED'):
                subscription_id=str(external_subscription or pedido_checkout['asaas_subscription_id'] or '')
                if subscription_id:
                    conn.execute('UPDATE assinaturas SET status=?,atualizado_em=? WHERE hotel_id=? AND assinatura_externa=?',
                                 ('SUSPENSA',now,hotel_id,subscription_id))
                conn.execute('UPDATE checkout_assinaturas SET status=?,atualizado_em=? WHERE id=?',('SUSPENSA',now,local_id))
                status_evento='PROCESSADO'
            elif event_type in ('CHECKOUT_PAID','PAYMENT_CONFIRMED','PAYMENT_RECEIVED'):
                plano=conn.execute('SELECT id,dias_ciclo,preco_mensal FROM planos WHERE id=? AND ativo=1',(pedido_checkout['plano_id'],)).fetchone()
                payment_id=str(payment.get('id') or '').strip()
                if event_type=='CHECKOUT_PAID' and not payment_id:
                    payment_id='checkout:'+str(checkout_id or pedido_checkout['checkout_id'] or local_id)
                if not plano or not payment_id:
                    status_evento='REVISAR'
                else:
                    valor=payment.get('value')
                    if event_type=='CHECKOUT_PAID' and valor is None:
                        try:
                            itens=checkout.get('items') or []
                            valor=sum(float(item.get('value') or 0)*float(item.get('quantity') or 0) for item in itens if isinstance(item,dict))
                        except (TypeError,ValueError):
                            valor=None
                    try:
                        valor_invalido=valor is not None and abs(float(valor)-float(plano['preco_mensal']))>0.01
                    except (TypeError,ValueError):
                        valor_invalido=True
                    ja_processado=conn.execute('SELECT payment_id FROM asaas_pagamentos_processados WHERE payment_id=?',(payment_id,)).fetchone()
                    pagamento_deste_checkout=conn.execute('SELECT payment_id FROM asaas_pagamentos_processados WHERE checkout_local_id=? LIMIT 1',(local_id,)).fetchone()
                    data_criacao_pagamento=str(payment.get('dateCreated') or payment.get('confirmedDate') or payment.get('paymentDate') or '')[:10]
                    data_checkout_pago=str(pedido_checkout['pago_em'] or '')[:10]
                    primeiro_pagamento_ja_ativou=(event_type=='CHECKOUT_PAID' and bool(pagamento_deste_checkout)) or (
                        event_type in ('PAYMENT_CONFIRMED','PAYMENT_RECEIVED') and pedido_checkout['status']=='ATIVA' and
                        bool(data_criacao_pagamento and data_checkout_pago and data_criacao_pagamento<=data_checkout_pago))
                    if valor_invalido:
                        status_evento='VALOR_DIVERGENTE'
                    elif ja_processado or primeiro_pagamento_ja_ativou:
                        status_evento='PAGAMENTO_DUPLICADO'
                    else:
                        conn.execute('INSERT INTO asaas_pagamentos_processados (payment_id,checkout_local_id,processado_em) VALUES (?,?,?)',
                                     (payment_id,local_id,now))
                        atual=conn.execute('SELECT * FROM assinaturas WHERE hotel_id=? ORDER BY id DESC LIMIT 1',(hotel_id,)).fetchone()
                        if not atual:
                            ensure_subscription_for_hotel(conn.cursor(),hotel_id)
                            atual=conn.execute('SELECT * FROM assinaturas WHERE hotel_id=? ORDER BY id DESC LIMIT 1',(hotel_id,)).fetchone()
                        hoje=saas_local_now().date()
                        try:
                            fim_atual=datetime.date.fromisoformat(str(atual['periodo_fim'])[:10]) if atual and atual['periodo_fim'] else hoje
                        except ValueError:
                            fim_atual=hoje
                        base=fim_atual if atual and atual['status']=='ATIVA' and fim_atual>=hoje else hoje
                        novo_fim=base+datetime.timedelta(days=int(plano['dias_ciclo'] or 30))
                        conn.execute('''UPDATE assinaturas SET plano_id=?,status='ATIVA',inicio=?,periodo_fim=?,trial_ate=NULL,
                                        gateway=?,checkout_externo=?,assinatura_externa=?,atualizado_em=? WHERE id=?''',
                                     (pedido_checkout['plano_id'],(atual['inicio'] if atual and atual['status']=='ATIVA' else hoje.isoformat()),
                                      novo_fim.isoformat(),'asaas:'+os.getenv('ASAAS_ENV','sandbox'),
                                      str(pedido_checkout['checkout_id'] or checkout_id or ''),
                                      str(external_subscription or pedido_checkout['asaas_subscription_id'] or '') or None,now,atual['id']))
                        conn.execute('UPDATE checkout_assinaturas SET status=?,pago_em=?,atualizado_em=? WHERE id=?',
                                     ('ATIVA',now,now,local_id))
                        status_evento='PROCESSADO'
            elif event_type=='SUBSCRIPTION_CREATED':
                status_evento='PROCESSADO'
            else:
                status_evento='RECEBIDO'

        conn.execute('UPDATE webhook_eventos SET status=?,processado_em=? WHERE provider=? AND event_id=?',
                     (status_evento,now,'asaas',event_id))
        conn.commit()
        return jsonify({'ok':True,'status':status_evento,'event_id':event_id}),200
    except Exception:
        conn.rollback()
        app.logger.exception('Falha ao processar webhook Asaas, evento %s',event_id)
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

@app.route('/api/platform/metricas')
@token_required
def platform_metricas(current_user,role):
    if role!='platform_admin': return jsonify({'erro':'Acesso restrito ao administrador do SaaS.'}),403
    conn=get_db()
    try:
        hoje=saas_local_now().date(); inicio_mes=hoje.replace(day=1); inicio_30=hoje-datetime.timedelta(days=29)
        hotels=conn.execute('SELECT id,nome,data_cadastro,bloqueado FROM hoteis').fetchall()
        mrr=0.0; ativas=teste=canceladas=onboardings=inadimplentes=sem_setup=0; quartos_total=reservas_mes=checkins_hoje=checkouts_hoje=0
        for h in hotels:
            hid=h['id']; sub=get_subscription(conn,hid)
            if sub:
                if sub['status']=='ATIVA' and sub.get('ativo'):
                    ativas+=1; mrr+=float(sub.get('preco_mensal') or 0)
                elif sub['status']=='TESTE' and sub.get('ativo'): teste+=1
                elif sub['status']=='CANCELADA' and str(sub.get('atualizado_em') or '')[:10]>=inicio_30.isoformat(): canceladas+=1
                if sub['status']=='ATIVA' and not sub.get('ativo'): inadimplentes+=1
            inicio=str(h['data_cadastro'] or '')[:10]
            try:
                if inicio and datetime.date.fromisoformat(inicio)>=inicio_30: onboardings+=1
            except ValueError: pass
            qtd_quartos=int(conn.execute('SELECT COUNT(*) AS n FROM quartos WHERE hotel_id=?',(hid,)).fetchone()['n'] or 0)
            quartos_total+=qtd_quartos
            if qtd_quartos==0: sem_setup+=1
            reservas_mes+=int(conn.execute("SELECT COUNT(*) AS n FROM reservas WHERE hotel_id=? AND status<>'CANCELADA' AND check_in>=? AND check_in<=?",(hid,inicio_mes.isoformat(),hoje.isoformat())).fetchone()['n'] or 0)
            checkins_hoje+=int(conn.execute("SELECT COUNT(*) AS n FROM reservas WHERE hotel_id=? AND status<>'CANCELADA' AND check_in=?",(hid,hoje.isoformat())).fetchone()['n'] or 0)
            checkouts_hoje+=int(conn.execute("SELECT COUNT(*) AS n FROM reservas WHERE hotel_id=? AND status<>'CANCELADA' AND check_out=?",(hid,hoje.isoformat())).fetchone()['n'] or 0)
        db_start=time.monotonic()
        conn.execute('SELECT 1').fetchone()
        db_ms=round((time.monotonic()-db_start)*1000,2)
        falhas_webhook=int(conn.execute("SELECT COUNT(*) AS n FROM webhook_eventos WHERE status='ERRO' AND recebido_em>=?",(inicio_30.isoformat(),)).fetchone()['n'] or 0)
        tickets_abertos=int(conn.execute("SELECT COUNT(*) AS n FROM suporte_tickets WHERE status<>'RESOLVIDO'").fetchone()['n'] or 0)
        tempos=[]
        for t in conn.execute('SELECT criado_em,primeira_resposta_em FROM suporte_tickets WHERE primeira_resposta_em IS NOT NULL').fetchall():
            try:
                a=datetime.datetime.fromisoformat(t['criado_em']); b=datetime.datetime.fromisoformat(t['primeira_resposta_em']); tempos.append(max(0.0,(b-a).total_seconds()/3600))
            except (TypeError,ValueError): pass
        sla_medio=sum(tempos)/len(tempos) if tempos else None
        uso_modulos=[dict(x) for x in conn.execute('SELECT module,COUNT(*) AS acessos FROM saas_module_usage WHERE accessed_at>=? GROUP BY module ORDER BY acessos DESC',(inicio_30.isoformat(),)).fetchall()]
        cac_raw=os.getenv('SAAS_CAC_ESTIMADO','').strip()
        try: cac=float(cac_raw) if cac_raw else None
        except ValueError: cac=None
        arpa=mrr/ativas if ativas else 0
        churn=canceladas/max(ativas+canceladas,1) if canceladas else 0
        ltv=(arpa/churn) if churn>0 else None
        return jsonify({'data':hoje.isoformat(),'clientes':len(hotels),'assinaturas_ativas':ativas,'em_teste':teste,
            'inadimplentes':inadimplentes,'canceladas':canceladas,'onboardings_30d':onboardings,'onboarding_sem_quartos':sem_setup,'mrr':round(mrr,2),'arr':round(mrr*12,2),
            'churn_estimado_30d_percentual':round(churn*100,2),'ltv_estimado':round(ltv,2) if ltv is not None else None,
            'cac':cac,'ltv_cac':round(ltv/cac,2) if ltv is not None and cac and cac>0 else None,
            'quartos_cadastrados':quartos_total,'reservas_mes':reservas_mes,'checkins_hoje':checkins_hoje,'checkouts_hoje':checkouts_hoje,
            'webhooks_com_erro_30d':falhas_webhook,'tickets_abertos':tickets_abertos,'sla_media_primeira_resposta_horas':round(sla_medio,2) if sla_medio is not None else None,'uso_modulos_30d':uso_modulos,'infra':{'banco':'PostgreSQL' if getattr(conn,'is_postgres',False) else 'SQLite','banco_responde':True,'latencia_ms':db_ms},
            'integracoes':{'asaas_configurado':bool(os.getenv('ASAAS_API_KEY','').strip() and os.getenv('ASAAS_WEBHOOK_TOKEN','').strip() and os.getenv('SAAS_PUBLIC_URL','').strip()),
            'geoapify_configurado':bool(os.getenv('GEOAPIFY_API_KEY','').strip()),
            'geoapify_maps_configurado':bool(os.getenv('GEOAPIFY_MAPS_API_KEY','').strip()),
                'whatsapp_configurado':bool(os.getenv('WHATSAPP_CLOUD_API_ACCESS_TOKEN','').strip() and os.getenv('WHATSAPP_CLOUD_API_PHONE_NUMBER_ID','').strip()),
                'booking_api':'requer credenciais e aprovação de parceiro','airbnb_api':'requer credenciais de parceiro','expedia_api':'requer credenciais de parceiro'}}),200
    finally: conn.close()

@app.route('/api/telemetria/modulo',methods=['POST'])
@token_required
def registrar_uso_modulo(current_user,role):
    permitidos={'painel','quartos','categorias','reservas','servicos','ordens','equipe','estoque','financeiro','relatorios','integracoes','whatsapp','suporte'}
    if not g.hotel_id: return jsonify({'ok':True}),200
    data=request.get_json(silent=True) or {}; modulo=str(data.get('module') or '')
    if modulo not in permitidos: return jsonify({'erro':'Módulo inválido.'}),400
    conn=get_db()
    try:
        conn.execute('INSERT INTO saas_module_usage (hotel_id,module,accessed_at) VALUES (?,?,?)',(g.hotel_id,modulo,utc_now_iso()))
        conn.commit(); return jsonify({'ok':True}),201
    finally: conn.close()

@app.route('/api/suporte/tickets',methods=['GET','POST'])
@token_required
def suporte_tickets(current_user,role):
    if not g.hotel_id: return jsonify({'erro':'Este perfil não pertence a um hotel.'}),403
    conn=get_db()
    try:
        if request.method=='POST':
            data=request.get_json(silent=True) or {}; assunto=str(data.get('assunto') or '').strip()[:160]; mensagem=str(data.get('mensagem') or '').strip()[:5000]
            ticket_id=data.get('ticket_id')
            if len(mensagem)<8: return jsonify({'erro':'A mensagem precisa ter pelo menos 8 caracteres.'}),400
            if ticket_id:
                try: ticket_id=int(ticket_id)
                except (TypeError,ValueError): return jsonify({'erro':'Chamado inválido.'}),400
                ticket=conn.execute("SELECT id,status FROM suporte_tickets WHERE id=? AND hotel_id=?",(ticket_id,g.hotel_id)).fetchone()
                if not ticket: return jsonify({'erro':'Chamado não encontrado.'}),404
                if ticket['status']=='RESOLVIDO': return jsonify({'erro':'O chamado está resolvido. Abra outro para um novo assunto.'}),409
                now=utc_now_iso(); conn.execute('INSERT INTO suporte_mensagens (ticket_id,autor_id,autor_role,mensagem,criado_em) VALUES (?,?,?,?,?)',(ticket_id,g.current_user_id,role,mensagem,now)); conn.execute("UPDATE suporte_tickets SET atualizado_em=?,status='ABERTO' WHERE id=?",(now,ticket_id)); conn.commit()
                return jsonify({'mensagem':'Resposta adicionada.','id':ticket_id}),200
            if len(assunto)<4: return jsonify({'erro':'Informe um assunto com pelo menos 4 caracteres.'}),400
            now=utc_now_iso(); cur=conn.cursor(); cur.execute("INSERT INTO suporte_tickets (hotel_id,assunto,prioridade,status,criado_por,criado_em,atualizado_em) VALUES (?,?,?,'ABERTO',?,?,?)",(g.hotel_id,assunto,str(data.get('prioridade') or 'NORMAL').upper() if str(data.get('prioridade') or 'NORMAL').upper() in ('BAIXA','NORMAL','ALTA') else 'NORMAL',g.current_user_id,now,now)); ticket_id=cur.lastrowid
            conn.execute('INSERT INTO suporte_mensagens (ticket_id,autor_id,autor_role,mensagem,criado_em) VALUES (?,?,?,?,?)',(ticket_id,g.current_user_id,role,mensagem,now)); conn.commit()
            return jsonify({'mensagem':'Chamado aberto.','id':ticket_id}),201
        rows=conn.execute('SELECT id,assunto,prioridade,status,criado_em,atualizado_em,primeira_resposta_em FROM suporte_tickets WHERE hotel_id=? ORDER BY atualizado_em DESC',(g.hotel_id,)).fetchall(); out=[]
        for row in rows:
            ticket=dict(row); ticket['mensagens']=[dict(x) for x in conn.execute('SELECT autor_role,mensagem,criado_em FROM suporte_mensagens WHERE ticket_id=? ORDER BY id',(row['id'],)).fetchall()]; out.append(ticket)
        return jsonify(out),200
    finally: conn.close()

@app.route('/api/platform/tickets',methods=['GET'])
@token_required
def platform_listar_tickets(current_user,role):
    if role!='platform_admin': return jsonify({'erro':'Acesso restrito ao administrador do SaaS.'}),403
    conn=get_db()
    try:
        rows=conn.execute("SELECT t.*,h.nome AS hotel_nome FROM suporte_tickets t JOIN hoteis h ON h.id=t.hotel_id ORDER BY CASE WHEN t.status='RESOLVIDO' THEN 1 ELSE 0 END,t.atualizado_em").fetchall(); out=[]
        for row in rows:
            ticket=dict(row); ticket['mensagens']=[dict(x) for x in conn.execute('SELECT autor_role,mensagem,criado_em FROM suporte_mensagens WHERE ticket_id=? ORDER BY id',(row['id'],)).fetchall()]; out.append(ticket)
        return jsonify(out),200
    finally: conn.close()

@app.route('/api/platform/tickets/<int:ticket_id>',methods=['PUT'])
@token_required
def platform_responder_ticket(current_user,role,ticket_id):
    if role!='platform_admin': return jsonify({'erro':'Acesso restrito ao administrador do SaaS.'}),403
    data=request.get_json(silent=True) or {}; resposta=str(data.get('resposta') or '').strip()[:5000]; status=str(data.get('status') or 'EM_ATENDIMENTO').upper()
    if status not in ('ABERTO','EM_ATENDIMENTO','AGUARDANDO_CLIENTE','RESOLVIDO'): return jsonify({'erro':'Status de chamado inválido.'}),400
    conn=get_db()
    try:
        ticket=conn.execute('SELECT id FROM suporte_tickets WHERE id=?',(ticket_id,)).fetchone()
        if not ticket: return jsonify({'erro':'Chamado não encontrado.'}),404
        now=utc_now_iso(); conn.execute('UPDATE suporte_tickets SET status=?,atualizado_em=?,primeira_resposta_em=COALESCE(primeira_resposta_em,?) WHERE id=?',(status,now,now if resposta else None,ticket_id))
        if resposta: conn.execute('INSERT INTO suporte_mensagens (ticket_id,autor_id,autor_role,mensagem,criado_em) VALUES (?,?,?,?,?)',(ticket_id,g.current_user_id,'platform_admin',resposta,now))
        conn.commit(); return jsonify({'mensagem':'Chamado atualizado.'}),200
    finally: conn.close()

@app.route('/api/platform/usuarios')
@token_required
def platform_usuarios(current_user,role):
    if role!='platform_admin': return jsonify({'erro':'Acesso restrito ao administrador do SaaS.'}),403
    conn=get_db()
    try:
        rows=conn.execute('''
            SELECT u.id,u.nome,u.username,u.email,u.role,u.ativo,u.ultimo_login,
                   h.id AS hotel_id,h.nome AS hotel_nome
            FROM usuarios u LEFT JOIN hoteis h ON h.id=u.hotel_id
            WHERE u.role<>'platform_admin'
            ORDER BY h.nome,u.nome,u.username
        ''').fetchall()
        return jsonify([dict(row) for row in rows]),200
    finally: conn.close()

@app.route('/api/platform/usuarios/<int:user_id>/status',methods=['PUT'])
@token_required
def platform_atualizar_usuario(current_user,role,user_id):
    if role!='platform_admin': return jsonify({'erro':'Acesso restrito ao administrador do SaaS.'}),403
    data=request.get_json(silent=True) or {}
    ativo=data.get('ativo')
    if not isinstance(ativo,bool): return jsonify({'erro':'Informe ativo como true ou false.'}),400
    conn=get_db()
    try:
        target=conn.execute('SELECT id,role FROM usuarios WHERE id=?',(user_id,)).fetchone()
        if not target: return jsonify({'erro':'Usuário não encontrado.'}),404
        if target['role']=='platform_admin': return jsonify({'erro':'Contas de administrador SaaS não podem ser suspensas por esta tela.'}),403
        conn.execute('UPDATE usuarios SET ativo=? WHERE id=?',(1 if ativo else 0,user_id))
        conn.commit()
        return jsonify({'mensagem':'Acesso reativado.' if ativo else 'Acesso suspenso.','usuario_id':user_id,'ativo':ativo}),200
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
                     (1 if bloquear else 0,utc_now_iso() if bloquear else None,motivo if bloquear else None,hotel_id))
        conn.commit()
        return jsonify({'mensagem':'Hotel bloqueado.' if bloquear else 'Hotel liberado.','hotel_id':hotel_id}),200
    finally: conn.close()

@app.route('/api/platform/assinaturas/<int:hotel_id>',methods=['PUT'])
@token_required
def platform_atualizar_assinatura(current_user,role,hotel_id):
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
        hoje=saas_local_now().date(); fim=hoje+datetime.timedelta(days=dias)
        cur=conn.cursor()
        cur.execute('INSERT INTO assinaturas (hotel_id,plano_id,status,inicio,periodo_fim,trial_ate,gateway,atualizado_em) VALUES (?,?,?,?,?,?,?,?)',
                    (hotel_id,plano_id,status,hoje.isoformat(),fim.isoformat() if status!='CANCELADA' else None,fim.isoformat() if status=='TESTE' else None,'plataforma',utc_now_iso()))
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







if __name__ == '__main__':
    app.run(host=os.getenv('HOST','0.0.0.0'), port=int(os.getenv('PORT','5000')), debug=os.getenv('FLASK_DEBUG','0').lower() in ('1','true','yes'))
