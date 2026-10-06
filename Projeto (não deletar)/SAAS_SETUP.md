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
