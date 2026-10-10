# Hotel Master — SaaS: PostgreSQL, Geoapify e Asaas

## Executar no seu próprio computador

O `app.py` lê um arquivo `.env` na pasta do projeto e não substitui variáveis que já existam no Windows. O `.env` está no `.gitignore`, então as chaves ficam fora do Git.

No PowerShell, na pasta do projeto, copie o modelo e abra para edição:

    Copy-Item env.example .env
    notepad .env

Para desenvolvimento local, deixe `DATABASE_URL` vazio para usar o SQLite `hotel.db`, mantenha `APP_ENV=development`, `FORCE_HTTPS=0`, `SESSION_COOKIE_SECURE=0` e ajuste `SAAS_TIMEZONE_OFFSET=-03:00` (Brasília; use o offset da operação do hotel). Troque `FLASK_SECRET_KEY` e `JWT_SECRET` por dois segredos diferentes. Gere cada um no terminal com `python -c "import secrets; print(secrets.token_urlsafe(48))"` e cole os resultados no `.env`. Depois inicie com `python app.py` no mesmo diretório e acesse `http://127.0.0.1:5000`.

Para ativar pesquisa de endereço e mapa, crie no Geoapify uma chave para Geocoding e configure `GEOAPIFY_API_KEY` no `.env`. A chave é usada pelo servidor e não deve ser colocada no JavaScript. Para o mapa estático, configure uma segunda chave em `GEOAPIFY_MAPS_API_KEY` e restrinja-a por HTTP referrer/origem. Em desenvolvimento local, permita `http://127.0.0.1:5000/*` e `http://localhost:5000/*`; em produção, permita apenas o domínio do SaaS. No painel Geoapify, para testar busca por endereço ou local, selecione **Geocoding API** e use “Try”. A pesquisa no hotel usa `/v1/geocode/search`; o mapa usa Static Maps. Não publique a chave completa. Atribuição © Geoapify e © OpenStreetMap é exibida junto ao mapa.

Para ativar WhatsApp, preencha no `.env` `WHATSAPP_CLOUD_API_ACCESS_TOKEN`, `WHATSAPP_CLOUD_API_PHONE_NUMBER_ID` e `WHATSAPP_CLOUD_API_VERSION`; opcionalmente configure o nome/idioma do modelo aprovado. No sistema, abra **Equipe e acessos**, cadastre o telefone do funcionário com DDI e DDD e habilite a opção de notificações. A ordem de serviço é gravada mesmo se o envio falhar; a interface informa a situação retornada pela API.

Para o Asaas use `ASAAS_ENV=sandbox`, a chave de teste e um token de webhook. Como `localhost` não é acessível pelo Asaas, o webhook precisa de uma URL HTTPS pública encaminhada temporariamente ao seu computador por um túnel seguro. Configure essa URL em `SAAS_PUBLIC_URL` e no painel do Asaas, terminando em `/webhooks/asaas`. Para operação contínua e pagamentos reais, prefira publicar o SaaS em hospedagem com domínio HTTPS estável e banco PostgreSQL persistente.

## PostgreSQL

Em produção, defina `DATABASE_URL`:

```
postgresql://usuario:senha@host:5432/hotel_master
```

Quando `DATABASE_URL` existir, o `app.py` usa PostgreSQL. Sem essa variável, o sistema continua usando o SQLite local para não quebrar o ambiente de desenvolvimento.

Defina `SAAS_TIMEZONE_OFFSET` para o fuso local dos hotéis, no formato `-03:00` (padrão São Paulo), para que os relatórios diários e as movimentações de check-in/check-out usem o dia operacional correto.

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

## Geoapify (pesquisa de endereço e mapa)

Defina:

```
GEOAPIFY_API_KEY=SUA_CHAVE_DE_GEOCODING
GEOAPIFY_MAPS_API_KEY=SUA_CHAVE_DE_MAPA_RESTRITA_POR_DOMINIO
```

O painel possui a aba **Integrações**. Cada hotel pode salvar Booking.com, Airbnb, Expedia, Hoteis.com, site próprio, link do mapa, endereço e coordenadas.

Os atalhos de Booking.com e Airbnb abrem os extranets oficiais em outra aba para o proprietário editar fotos, tarifas, promoções e condições. Sincronizar e editar esses anúncios diretamente dentro do Hotel Master exige credenciais e aprovação de parceiro de cada OTA; URLs públicas de anúncios não autorizam alterações por API.

A pesquisa de local usa a Geocoding API do Geoapify. Para consultas de endereço ou nome de local, escolha **Geocoding API** no seletor de API do painel Geoapify. Para categorias de pontos de interesse, a Places API é outro produto e não é a API usada nesta tela.

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

## WhatsApp para ordens de serviço

O hotel informa o número oficial na aba **Integrações**. No cadastro de cada funcionário, informe o telefone internacional com DDI e DDD e marque a autorização de recebimento. Para habilitar os avisos automáticos, configure no ambiente do servidor `WHATSAPP_CLOUD_API_ACCESS_TOKEN`, `WHATSAPP_CLOUD_API_PHONE_NUMBER_ID` e `WHATSAPP_CLOUD_API_VERSION` com os dados da conta WhatsApp Business Cloud API. O valor da versão deve ser uma versão Graph API ativa na sua conta.

Ordens são salvas mesmo se o envio falhar; a tela informa quando faltam configurações ou quando não foi possível enviar. Para mensagens iniciadas pelo hotel fora da janela de atendimento, crie e aprove um modelo de utilidade na Meta com sete variáveis no corpo, na ordem: número da OS, quarto/andar, serviço, funcionário, solicitante, prioridade e descrição. Configure `WHATSAPP_CLOUD_API_TEMPLATE_NAME` e `WHATSAPP_CLOUD_API_TEMPLATE_LANGUAGE` com o nome e idioma do modelo aprovado. Sem modelo, o sistema tenta uma mensagem de texto comum, sujeita à janela de atendimento do WhatsApp. Não coloque tokens reais no `env.example` nem no Git.

## Segurança

Nunca coloque API Keys, tokens do Asaas, senhas PostgreSQL ou chaves Flask dentro do GitHub.

Use as variáveis de ambiente do servidor e mantenha `.env` fora do controle de versão.


## Hospedagem gratuita para testes

Uma combinação prática para começar sem custo é:

1. Render Free para o Flask/Gunicorn.
2. Neon Free para o PostgreSQL.
3. Geoapify e Asaas como serviços externos, somente quando você precisar das integrações.

A instância gratuita do Render para aplicações web Python é adequada para testes e projetos pessoais, mas entra em suspensão após 15 minutos sem tráfego e pode levar cerca de um minuto para voltar. O filesystem local é efêmero; por isso, não use o hotel.db como banco de produção no Render. O PostgreSQL deve ficar externo. O PostgreSQL gratuito do Render expira após 30 dias, então não o recomendo para a base principal deste SaaS.

O Neon informa atualmente 1 GB de PostgreSQL por projeto no plano gratuito. Para este projeto inicial, ele é uma opção simples para manter o banco separado do servidor.

### Configuração no Render

Conecte o repositório GitHub e crie um Web Service. Selecione esta pasta como
**Root Directory** no Render e use:

Build Command
    pip install -r requirements.txt

Start Command
    gunicorn --preload --workers 2 --threads 4 --timeout 120 app:app

O arquivo `Procfile` já contém o comando de inicialização. Configure o diretório raiz
do serviço para a pasta deste projeto e defina as variáveis de ambiente:

    DATABASE_URL=<URL do Neon>
    FLASK_SECRET_KEY=<chave aleatória forte>
    JWT_SECRET=<outra chave aleatória forte>
    SESSION_COOKIE_SECURE=1
    FORCE_HTTPS=1
    SAAS_PUBLIC_URL=https://SEU-ENDERECO.onrender.com
    FLASK_DEBUG=0

As chaves `FLASK_SECRET_KEY` e `JWT_SECRET` devem ser valores aleatórios diferentes.
As chaves da Geoapify Platform e do Asaas pertencem às respectivas contas do
operador; não existe chave segura que possa ser pré-preenchida no código. Use o
Asaas em sandbox durante a homologação e só mude `ASAAS_ENV=producao` depois de
configurar e validar credenciais e webhook no painel do Asaas.

Para gerar as duas chaves no seu computador:

    python -c "import secrets; print(secrets.token_urlsafe(48))"

Execute o comando duas vezes e use valores diferentes.

### Primeiro acesso do administrador do SaaS

O hotel.db que está no repositório foi reinicializado para conter somente o perfil de administrador do SaaS. Esse banco local serve para o modo SQLite.

Quando você utilizar PostgreSQL, o init_db() cria as tabelas e o administrador inicial poderá ser criado por variáveis de ambiente:

    SAAS_ADMIN_INITIAL_USERNAME=Administrado
    SAAS_ADMIN_INITIAL_PASSWORD=<senha inicial forte>

Depois do primeiro login, remova SAAS_ADMIN_INITIAL_PASSWORD das variáveis do servidor. A senha continua armazenada como hash. A senha solicitada na conversa (“Senha do Administrador”) não é aceita como senha inicial porque não contém número; use uma senha exclusiva, longa e aleatória. Não coloque uma senha conhecida/padrão no código ou no Git.

### Métricas e painel do administrador

O administrador do SaaS acessa o painel **Administração SaaS**. O MRR soma os planos de assinaturas ativas e vigentes; o ARR é MRR × 12. Cancelamentos e churn são estimativas com o histórico disponível nas assinaturas atuais, portanto não substituem uma trilha de eventos completa. LTV/CAC só aparece quando existe churn observável e `SAAS_CAC_ESTIMADO` está configurado no ambiente como custo médio de aquisição por cliente (em reais). O painel também verifica resposta/latência do banco e credenciais do Asaas, Geoapify e WhatsApp. Presença de credenciais não significa que uma chamada externa foi testada com sucesso.

O Asaas confirma pagamentos pelo webhook e o sistema registra eventos repetidos sem processá-los novamente. Para acompanhar a conexão, configure `ASAAS_API_KEY`, `ASAAS_WEBHOOK_TOKEN`, `ASAAS_ENV` e `SAAS_PUBLIC_URL` no serviço de hospedagem e aponte o webhook para `/webhooks/asaas`. Comece em sandbox. Nunca exponha tokens no navegador ou no repositório.

Para ativar as demais integrações, configure `GEOAPIFY_API_KEY` para Geocoding, `GEOAPIFY_MAPS_API_KEY` para o mapa e `WHATSAPP_CLOUD_API_ACCESS_TOKEN`, `WHATSAPP_CLOUD_API_PHONE_NUMBER_ID` e `WHATSAPP_CLOUD_API_VERSION` para a WhatsApp Cloud API. Booking.com, Airbnb e Expedia atualmente têm links para as extranets, não sincronização por API: para editar anúncios ou sincronizar disponibilidade/tarifas pelo sistema, solicite acesso e credenciais de integração aos respectivos programas de parceiros e implemente/homologue cada API antes de anunciar a conexão como ativa.

O monitor do painel mede uma consulta simples ao banco e a presença das credenciais configuradas; ele não mede CPU/memória nem executa uma chamada de teste em cada serviço externo. O módulo de suporte registra tickets por hotel e o tempo médio até a primeira resposta, calculado apenas sobre chamados respondidos. O uso de módulos conta acessos às abas nos últimos 30 dias, sem registrar os dados operacionais consultados.

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
