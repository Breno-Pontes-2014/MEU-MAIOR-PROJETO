document.addEventListener('DOMContentLoaded', () => {
    const token = localStorage.getItem('token');
    if (!token) {
        window.location.href = '/login';
        return;
    }

    const tabButtons = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    tabButtons.forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            tabButtons.forEach(b => b.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));

            btn.classList.add('active');
            const targetId = btn.getAttribute('data-target');
            document.getElementById(targetId).classList.add('active');
        });
    });

    const btnLogout = document.getElementById('btnLogout');
    if (btnLogout) {
        btnLogout.addEventListener('click', () => {
            localStorage.clear();
            window.location.href = '/login';
        });
    }

    carregarPerfil();
    carregarQuartos();
    carregarHospedes();
    carregarReservas();
    carregarEstoque();
    carregarFinanceiro();
    carregarOs();
    carregarRelatorios();

    async function carregarPerfil() {
        try {
            const res = await fetch('/api/me', { headers: { 'Authorization': `Bearer ${token}` } });
            if (res.ok) {
                const data = await res.json();
                const displayUsername = document.getElementById('displayUsername');
                const displayRole = document.getElementById('displayRole');
                const userAvatar = document.getElementById('userAvatar');
                
                if (displayUsername) displayUsername.innerText = data.username;
                if (displayRole) displayRole.innerText = data.role.toUpperCase();
                if (userAvatar) userAvatar.innerText = data.username.charAt(0).toUpperCase();

                // Exibir menu de admin se o utilizador for admin
                const adminMenuLink = document.getElementById('adminMenuLink');
                if (adminMenuLink && (data.role === 'admin' || data.role === 'master')) {
                    adminMenuLink.style.display = 'block';
                }
            } else {
                localStorage.clear();
                window.location.href = '/login';
            }
        } catch (err) {
            console.error('Erro ao carregar perfil:', err);
        }
    }

    async function carregarQuartos() {
        try {
            const res = await fetch('/api/quartos', { headers: { 'Authorization': `Bearer ${token}` } });
            const quartos = await res.json();
            
            const tabelaQuartosBody = document.getElementById('tabelaQuartosBody');
            if (tabelaQuartosBody) {
                tabelaQuartosBody.innerHTML = quartos.map(q => `
                    <tr>
                        <td><strong>${q.numero}</strong></td>
                        <td>${q.tipo}</td>
                        <td>R$ ${q.preco_diaria.toFixed(2)}</td>
                        <td><span class="btn-status ${q.status === 'DISPONIVEL' ? 'pago' : 'pendente'}">${q.status}</span></td>
                        <td><button class="btn-action delete" onclick="deletarQuarto('${q.numero}')">Excluir</button></td>
                    </tr>
                `).join('');
            }

            const resQuartoSelect = document.getElementById('resQuartoSelect');
            if (resQuartoSelect) {
                resQuartoSelect.innerHTML = quartos.filter(q => q.status === 'DISPONIVEL').map(q => `
                    <option value="${q.numero}">Quarto ${q.numero} (${q.tipo} - R$ ${q.preco_diaria})</option>
                `).join('');
            }
        } catch (err) {
            console.error('Erro ao carregar quartos:', err);
        }
    }

    async function carregarHospedes() {
        try {
            const res = await fetch('/api/hospedes', { headers: { 'Authorization': `Bearer ${token}` } });
            const hospedes = await res.json();
            
            const tabelaHospedesBody = document.getElementById('tabelaHospedesBody');
            if (tabelaHospedesBody) {
                tabelaHospedesBody.innerHTML = hospedes.map(h => `
                    <tr><td>#${h.id}</td><td><strong>${h.nome}</strong></td><td>${h.documento || '-'}</td><td>${h.telefone || '-'}</td><td>${h.email || '-'}</td></tr>
                `).join('');
            }

            const optionsHtml = hospedes.map(h => `<option value="${h.id}">${h.nome}</option>`).join('');
            const resHospedeSelect = document.getElementById('resHospedeSelect');
            const pdvHospedeSelect = document.getElementById('pdvHospedeSelect');
            
            if (resHospedeSelect) resHospedeSelect.innerHTML = optionsHtml;
            if (pdvHospedeSelect) pdvHospedeSelect.innerHTML = optionsHtml;
        } catch (err) {
            console.error('Erro ao carregar hóspedes:', err);
        }
    }

    async function carregarReservas() {
        try {
            const res = await fetch('/api/reservas', { headers: { 'Authorization': `Bearer ${token}` } });
            const reservas = await res.json();
            
            const tabelaReservasBody = document.getElementById('tabelaReservasBody');
            if (tabelaReservasBody) {
                tabelaReservasBody.innerHTML = reservas.map(r => `
                    <tr>
                        <td>#${r.id}</td><td>${r.hospede_nome}</td><td>Quarto ${r.quarto_numero}</td>
                        <td>${r.check_in}</td><td>${r.check_out}</td><td>R$ ${(r.valor_total || 0).toFixed(2)}</td>
                        <td><button class="btn-status ${r.status_pagamento ? r.status_pagamento.toLowerCase() : 'pendente'}" onclick="togglePagamento(${r.id})">${r.status_pagamento || 'Pendente'}</button></td>
                        <td><button class="btn-action delete" onclick="cancelarReserva(${r.id})">Cancelar</button></td>
                    </tr>
                `).join('');
            }
        } catch (err) {
            console.error('Erro ao carregar reservas:', err);
        }
    }

    async function carregarEstoque() {
        try {
            const res = await fetch('/api/estoque', { headers: { 'Authorization': `Bearer ${token}` } });
            const itens = await res.json();
            
            const tabelaEstoqueBody = document.getElementById('tabelaEstoqueBody');
            if (tabelaEstoqueBody) {
                tabelaEstoqueBody.innerHTML = itens.map(i => `
                    <tr><td>${i.item}</td><td>${i.categoria}</td><td>${i.quantidade}</td><td>R$ ${i.preco_unitario.toFixed(2)}</td></tr>
                `).join('');
            }

            const pdvItemSelect = document.getElementById('pdvItemSelect');
            if (pdvItemSelect) {
                pdvItemSelect.innerHTML = itens.map(i => `
                    <option value="${i.id}">${i.item} (Disponível: ${i.quantidade} - R$ ${i.preco_unitario})</option>
                `).join('');
            }
        } catch (err) {
            // Caso a tabela de estoque opcional não exista, ignora silenciosamente
        }
    }

    async function carregarFinanceiro() {
        try {
            const res = await fetch('/api/financeiro', { headers: { 'Authorization': `Bearer ${token}` } });
            const lancamentos = await res.json();
            
            const tabelaFinanceiroBody = document.getElementById('tabelaFinanceiroBody');
            if (tabelaFinanceiroBody) {
                tabelaFinanceiroBody.innerHTML = lancamentos.map(l => `
                    <tr>
                        <td><span class="btn-status ${l.tipo === 'ENTRADA' ? 'pago' : 'pendente'}">${l.tipo}</span></td>
                        <td>${l.categoria}</td><td>${l.descricao}</td><td>R$ ${l.valor.toFixed(2)}</td><td>${l.data}</td>
                    </tr>
                `).join('');
            }
        } catch (err) {
            console.error('Erro ao carregar financeiro:', err);
        }
    }

    async function carregarOs() {
        try {
            const res = await fetch('/api/os', { headers: { 'Authorization': `Bearer ${token}` } });
            const ordens = await res.json();
            
            const tabelaOsBody = document.getElementById('tabelaOsBody');
            if (tabelaOsBody) {
                tabelaOsBody.innerHTML = ordens.map(o => `
                    <tr><td>#${o.id}</td><td>Quarto ${o.quarto}</td><td>${o.tipo}</td><td>${o.descricao}</td><td>${o.status}</td></tr>
                `).join('');
            }
        } catch (err) {
            // Opcional se não implementado
        }
    }

    async function carregarRelatorios() {
        try {
            const res = await fetch('/api/relatorios', { headers: { 'Authorization': `Bearer ${token}` } });
            if (res.ok) {
                const data = await res.json();
                const relOcupacao = document.getElementById('relOcupacao');
                const relAdr = document.getElementById('relAdr');
                const relRevpar = document.getElementById('relRevpar');

                if (relOcupacao) relOcupacao.innerText = `${data.taxa_ocupacao || 0}%`;
                if (relAdr) relAdr.innerText = `R$ ${(data.adr || 0).toFixed(2)}`;
                if (relRevpar) relRevpar.innerText = `R$ ${(data.revpar || 0).toFixed(2)}`;
            }
        } catch (err) {
            console.error('Erro ao carregar relatórios:', err);
        }
    }

    // Event Listeners para Formulários
    const formHospede = document.getElementById('formHospede');
    if (formHospede) {
        formHospede.addEventListener('submit', async (e) => {
            e.preventDefault();
            await fetch('/api/hospedes', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
                body: JSON.stringify({
                    nome: document.getElementById('hNome').value,
                    documento: document.getElementById('hDoc').value,
                    telefone: document.getElementById('hTel').value,
                    email: document.getElementById('hEmail').value
                })
            });
            e.target.reset();
            carregarHospedes();
        });
    }

    const formQuarto = document.getElementById('formQuarto');
    if (formQuarto) {
        formQuarto.addEventListener('submit', async (e) => {
            e.preventDefault();
            await fetch('/api/quartos', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
                body: JSON.stringify({
                    numero: document.getElementById('qNumero').value,
                    tipo: document.getElementById('qTipo').value,
                    preco_diaria: parseFloat(document.getElementById('qPreco').value)
                })
            });
            e.target.reset();
            carregarQuartos();
        });
    }

    const formReserva = document.getElementById('formReserva');
    if (formReserva) {
        formReserva.addEventListener('submit', async (e) => {
            e.preventDefault();
            await fetch('/api/reservas', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
                body: JSON.stringify({
                    hospede_id: parseInt(document.getElementById('resHospedeSelect').value),
                    quarto_numero: document.getElementById('resQuartoSelect').value,
                    check_in: document.getElementById('resCheckIn').value,
                    check_out: document.getElementById('resCheckOut').value,
                    valor_total: parseFloat(document.getElementById('resValor').value)
                })
            });
            e.target.reset();
            carregarReservas();
            carregarQuartos();
            carregarFinanceiro();
            carregarRelatorios();
        });
    }

    const formPdv = document.getElementById('formPdv');
    if (formPdv) {
        formPdv.addEventListener('submit', async (e) => {
            e.preventDefault();
            const res = await fetch('/api/pdv/consumo', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
                body: JSON.stringify({
                    hospede_id: parseInt(document.getElementById('pdvHospedeSelect').value),
                    item_id: parseInt(document.getElementById('pdvItemSelect').value),
                    quantidade: parseInt(document.getElementById('pdvQtd').value)
                })
            });
            const data = await res.json();
            if(res.ok) {
                e.target.reset();
                carregarEstoque();
                alert(data.mensagem);
            } else {
                alert(data.erro);
            }
        });
    }

    const formFinanceiro = document.getElementById('formFinanceiro');
    if (formFinanceiro) {
        formFinanceiro.addEventListener('submit', async (e) => {
            e.preventDefault();
            await fetch('/api/financeiro', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
                body: JSON.stringify({
                    tipo: document.getElementById('finTipo').value,
                    categoria: document.getElementById('finCategoria').value,
                    descricao: document.getElementById('finDesc').value,
                    valor: parseFloat(document.getElementById('finValor').value)
                })
            });
            e.target.reset();
            carregarFinanceiro();
        });
    }

    const formOs = document.getElementById('formOs');
    if (formOs) {
        formOs.addEventListener('submit', async (e) => {
            e.preventDefault();
            await fetch('/api/os', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
                body: JSON.stringify({
                    quarto: document.getElementById('osQuarto').value,
                    tipo: document.getElementById('osTipo').value,
                    descricao: document.getElementById('osDesc').value
                })
            });
            e.target.reset();
            carregarOs();
        });
    }

    // Ações Globais
    window.togglePagamento = async function(id) {
        await fetch(`/api/reservas/${id}/pagamento`, { method: 'PUT', headers: { 'Authorization': `Bearer ${token}` } });
        carregarReservas();
        carregarFinanceiro();
        carregarRelatorios();
    };

    window.cancelarReserva = async function(id) {
        if(!confirm('Deseja cancelar esta reserva?')) return;
        await fetch(`/api/reservas/${id}`, { method: 'DELETE', headers: { 'Authorization': `Bearer ${token}` } });
        carregarReservas();
        carregarQuartos();
        carregarRelatorios();
    };

    window.deletarQuarto = async function(numero) {
        if(!confirm(`Excluir quarto ${numero}?`)) return;
        await fetch(`/api/quartos/${numero}`, { method: 'DELETE', headers: { 'Authorization': `Bearer ${token}` } });
        carregarQuartos();
    };
});