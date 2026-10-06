<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SGH - Gestão Hoteleira Completa</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
    <div class="app-layout">
        <aside class="sidebar">
            <div class="brand">
                <h2>🏨 Hotel Master</h2>
            </div>
            <div class="user-profile">
                <div class="avatar" id="userAvatar">U</div>
                <div class="info">
                    <span class="username" id="displayUsername">Carregando...</span>
                    <span class="role-tag" id="displayRole">...</span>
                </div>
            </div>
            <nav class="nav-menu">
                <a href="#" class="tab-btn active" data-target="tab-reservas">📅 Reservas & Datas</a>
                <a href="#" class="tab-btn" data-target="tab-quartos">🛏️ Gestão de Quartos</a>
                <a href="#" class="tab-btn" data-target="tab-hospedes">👥 Hóspedes</a>
                <a href="#" class="tab-btn" data-target="tab-financeiro">💰 Financeiro / Caixa</a>
                <!-- Visível apenas para Admins -->
                <a href="/cadastro-usuarios" id="adminMenuLink" style="display:none;" class="admin-link">⚙️ Gerenciar Usuários</a>
            </nav>
            <button id="btnLogout" class="btn-logout">Sair do Sistema</button>
        </aside>

        <main class="main-content">
            <section id="tab-reservas" class="tab-content active">
                <header class="top-header"><h1>Controle de Reservas, Períodos e Datas</h1></header>
                <div class="card-section">
                    <h3>Nova Reserva</h3>
                    <form id="formReserva" class="grid-form">
                        <div class="form-group"><label>Hóspede</label><select id="resHospedeSelect" required></select></div>
                        <div class="form-group"><label>Quarto Disponível</label><select id="resQuartoSelect" required></select></div>
                        <div class="form-group"><label>Data Check-in</label><input type="date" id="resCheckIn" required></div>
                        <div class="form-group"><label>Data Check-out</label><input type="date" id="resCheckOut" required></div>
                        <div class="form-group"><label>Valor Total (R$)</label><input type="number" step="0.01" id="resValor" required></div>
                        <div class="form-group full-width"><button type="submit" class="btn-primary">Confirmar Reserva</button></div>
                    </form>
                </div>
                <div class="card-section">
                    <h3>Lista de Reservas Ativas</h3>
                    <div class="table-container">
                        <table>
                            <thead>
                                <tr><th>ID</th><th>Hóspede</th><th>Quarto</th><th>Check-in</th><th>Check-out</th><th>Valor</th><th>Pagamento</th><th>Ações</th></tr>
                            </thead>
                            <tbody id="tabelaReservasBody"></tbody>
                        </table>
                    </div>
                </div>
            </section>

            <section id="tab-quartos" class="tab-content">
                <header class="top-header"><h1>Gestão de Quartos e Status</h1></header>
                <div class="card-section">
                    <h3>Cadastrar Novo Quarto</h3>
                    <form id="formQuarto" class="grid-form">
                        <div class="form-group"><label>Número</label><input type="text" id="qNumero" required></div>
                        <div class="form-group"><label>Tipo</label><input type="text" id="qTipo" required></div>
                        <div class="form-group"><label>Diária (R$)</label><input type="number" step="0.01" id="qPreco" required></div>
                        <div class="form-group full-width"><button type="submit" class="btn-primary">Salvar Quarto</button></div>
                    </form>
                </div>
                <div class="card-section">
                    <h3>Quartos Cadastrados</h3>
                    <div class="table-container">
                        <table>
                            <thead><tr><th>Número</th><th>Tipo</th><th>Diária</th><th>Status</th><th>Ações</th></tr></thead>
                            <tbody id="tabelaQuartosBody"></tbody>
                        </table>
                    </div>
                </div>
            </section>

            <section id="tab-hospedes" class="tab-content">
                <header class="top-header"><h1>Cadastro de Hóspedes</h1></header>
                <div class="card-section">
                    <h3>Novo Hóspede</h3>
                    <form id="formHospede" class="grid-form">
                        <div class="form-group"><label>Nome Completo</label><input type="text" id="hNome" required></div>
                        <div class="form-group"><label>Documento</label><input type="text" id="hDoc"></div>
                        <div class="form-group"><label>Telefone</label><input type="text" id="hTel"></div>
                        <div class="form-group"><label>E-mail</label><input type="email" id="hEmail"></div>
                        <div class="form-group full-width"><button type="submit" class="btn-primary">Salvar Hóspede</button></div>
                    </form>
                </div>
                <div class="card-section">
                    <h3>Hóspedes Cadastrados</h3>
                    <div class="table-container">
                        <table>
                            <thead><tr><th>ID</th><th>Nome</th><th>Documento</th><th>Telefone</th><th>E-mail</th></tr></thead>
                            <tbody id="tabelaHospedesBody"></tbody>
                        </table>
                    </div>
                </div>
            </section>

            <section id="tab-financeiro" class="tab-content">
                <header class="top-header"><h1>Relatório Financeiro e Caixa</h1></header>
                <div class="card-section">
                    <h3>Resumo de Entradas (Receitas Pagas)</h3>
                    <p style="font-size: 24px; font-weight: bold; color: #15803d; margin-top: 15px;" id="totalReceita">R$ 0,00</p>
                </div>
            </section>
        </main>
    </div>
    <script src="/static/script.js"></script>
</body>
</html>