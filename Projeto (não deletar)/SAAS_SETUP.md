# Hotel Master — SaaS: PostgreSQL, Google Maps e Asaas

## PostgreSQL

Em produção, defina `DATABASE_URL`:

```
postgresql://usuario:senha@host:5432/hotel_master
```

Quando `DATABASE_URL` existir, o `app.py` usa PostgreSQL. Sem essa variável, o sistema continua usando o SQLite local para não quebrar o ambiente de desenvolvimento.

Para migrar o banco existente:

```bash
cd "Projeto (não deletar)"
python migrate_sqlite_to_postgres.py
```

Ou informe explicitamente o SQLite:

```bash
python migrate_sqlite_to_postgres.py caminho/para/hotel.db
```

Faça um backup do SQLite antes da migração.

## Google Maps

Defina:

```
GOOGLE_MAPS_API_KEY=SUA_CHAVE
```

O painel possui a aba **Integrações**. Cada hotel pode salvar Booking.com, Airbnb, Expedia, Hoteis.com, site próprio, Google Maps, Place ID, endereço e coordenadas.

A pesquisa de local usa a **Places API (New) / Text Search**. Em produção, restrinja a chave de API no Google Cloud.

## Asaas

Para este SaaS, a recomendação é **Asaas**.

Defina:

```
ASAAS_API_KEY=SEU_ACCESS_TOKEN
ASAAS_WEBHOOK_TOKEN=SEU_TOKEN_DO_WEBHOOK
SAAS_PUBLIC_URL=https://seu-dominio.com.br
```

O endpoint do webhook é:

```
POST /webhooks/asaas
```

O Asaas deve enviar o token configurado no webhook no header:

```
asaas-access-token
```

O sistema salva o `event_id` antes do processamento e ignora reenvios do mesmo evento, mantendo idempotência.

Eventos de pagamento confirmados podem ativar a assinatura. Eventos de atraso suspendem e eventos de cancelamento inativam a assinatura.

## Segurança

Nunca coloque API Keys, tokens do Asaas, senhas PostgreSQL ou chaves Flask dentro do GitHub.

Use as variáveis de ambiente do servidor e mantenha `.env` fora do controle de versão.


## Hospedagem gratuita para testes

Uma combinação prática para começar sem custo é:

1. Render Free para o Flask/Gunicorn.
2. Neon Free para o PostgreSQL.
3. Google Maps e Asaas como serviços externos, somente quando você precisar das integrações.

A instância gratuita do Render para aplicações web Python é adequada para testes e projetos pessoais, mas entra em suspensão após 15 minutos sem tráfego e pode levar cerca de um minuto para voltar. O filesystem local é efêmero; por isso, não use o hotel.db como banco de produção no Render. O PostgreSQL deve ficar externo. O PostgreSQL gratuito do Render expira após 30 dias, então não o recomendo para a base principal deste SaaS.

O Neon informa atualmente 1 GB de PostgreSQL por projeto no plano gratuito. Para este projeto inicial, ele é uma opção simples para manter o banco separado do servidor.

### Configuração no Render

Conecte o repositório GitHub e crie um Web Service. Como o código está em uma subpasta, use:

Build Command
    pip install -r "Projeto (não deletar)/requirements.txt"

Start Command
    cd "Projeto (não deletar)" && gunicorn --workers 2 --threads 4 --timeout 120 app:app

Defina as variáveis de ambiente, principalmente:

    DATABASE_URL=<URL do Neon>
    FLASK_SECRET_KEY=<chave aleatória forte>
    JWT_SECRET=<outra chave aleatória forte>
    SESSION_COOKIE_SECURE=1
    FORCE_HTTPS=1
    SAAS_PUBLIC_URL=https://SEU-ENDERECO.onrender.com
    FLASK_DEBUG=0

Para gerar as duas chaves no seu computador:

    python -c "import secrets; print(secrets.token_urlsafe(48))"

Execute o comando duas vezes e use valores diferentes.

### Primeiro acesso do administrador do SaaS

O hotel.db que está no repositório foi reinicializado para conter somente o perfil de administrador do SaaS. Esse banco local serve para o modo SQLite.

Quando você utilizar PostgreSQL, o init_db() cria as tabelas e o administrador inicial poderá ser criado por variáveis de ambiente:

    SAAS_ADMIN_INITIAL_USERNAME=Breno
    SAAS_ADMIN_INITIAL_PASSWORD=<senha inicial forte>

Depois do primeiro login, remova SAAS_ADMIN_INITIAL_PASSWORD das variáveis do servidor. A senha continua armazenada como hash.

### PostgreSQL

Com o banco vazio no Neon, a aplicação cria a estrutura automaticamente na primeira inicialização.

Para migrar um banco SQLite existente para PostgreSQL, use:

    cd "Projeto (não deletar)"
    python migrate_sqlite_to_postgres.py hotel.db

Não faça essa migração sobre o banco novo que já foi criado para o administrador do SaaS. Migração de dados é uma etapa separada.

### Webhook do Asaas

Depois que o Render estiver publicado, cadastre no Asaas:

    https://SEU-ENDERECO.onrender.com/webhooks/asaas

No webhook do Asaas, utilize o token configurado em ASAAS_WEBHOOK_TOKEN. O sistema valida esse token e evita processar novamente o mesmo event_id.

### Regra de ouro para o banco

Render = aplicação
Neon = PostgreSQL persistente

Assim, reinícios ou novos deploys do servidor não apagam os dados dos hotéis.
