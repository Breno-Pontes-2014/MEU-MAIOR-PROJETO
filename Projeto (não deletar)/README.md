# Hotel Master SaaS

Sistema Flask de gestão hoteleira com autenticação por hotel, reservas, serviços, ordens de serviço, relatórios e administração SaaS.

## Execução local

1. Instale Python 3.10 ou superior.
2. Instale as dependências com: pip install -r requirements.txt.
3. Copie env.example para .env e preencha apenas as credenciais necessárias no computador ou servidor. Não publique o .env.
4. Inicie com python app.py e abra http://127.0.0.1:5000.

O banco local é hotel.db. Segredos locais e bancos estão excluídos do Git. O HTML e o JavaScript ativos são renderizados pelo Flask em app.py; as páginas antigas redirecionam para as rotas atuais.

## Publicação

Configure FLASK_SECRET_KEY, JWT_SECRET e DATABASE_URL como segredos do ambiente de produção. Configure as chaves das integrações no servidor; nunca em arquivos versionados.
