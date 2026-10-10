const CONTEXTO_USUARIO = window.HOTEL_MASTER_CONTEXT || {};
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

const menusTenant = [
  {id:'painel', icone:'PD', nome:'Painel', permissao:'reports.view'},
  {id:'quartos', icone:'QT', nome:'Quartos', permissao:'rooms.view'},
  {id:'categorias', icone:'CP', nome:'Categorias de pessoas', permissao:'categories.view'},
  {id:'reservas', icone:'RS', nome:'Reservas', permissao:'reservations.view'},
  {id:'servicos', icone:'SV', nome:'Serviços e pedidos', permissao:'services.view'},
  {id:'ordens', icone:'OS', nome:'Ordens de serviço', permissao:'orders.view'},
  {id:'equipe', icone:'EQ', nome:'Equipe e acessos', permissao:'team.view'},
  {id:'estoque', icone:'ET', nome:'Estoque', permissao:'stock.view'},
  {id:'financeiro', icone:'FN', nome:'Financeiro', permissao:'finance.view'},
  {id:'relatorios', icone:'RL', nome:'Relatórios', permissao:'reports.view'},
  {id:'integracoes', icone:'IN', nome:'Integrações', permissao:'integrations.view'},
  {id:'whatsapp', icone:'WA', nome:'WhatsApp', permissao:'whatsapp.use'}
  ,{id:'suporte', icone:'?', nome:'Suporte', permissao:'support.view'}
];
const rolePerms={
  admin:new Set(['*']),
  gerente:new Set(['rooms.view','rooms.manage','guests.view','guests.manage','categories.view','categories.manage','reservations.view','reservations.manage','reservations.pay','stock.view','stock.manage','finance.view','finance.manage','orders.view','orders.manage','services.view','services.manage','requests.view','requests.manage','reports.view','whatsapp.use','support.view']),
  recepcao:new Set(['rooms.view','guests.view','guests.manage','reservations.view','reservations.manage','reservations.pay','orders.view','orders.manage','services.view','requests.view','requests.manage','whatsapp.use','support.view']),
  limpeza:new Set(['rooms.view','orders.view','orders.manage','requests.view','requests.manage','support.view']),
  manutencao:new Set(['rooms.view','orders.view','orders.manage','requests.view','support.view']),
  financeiro:new Set(['rooms.view','guests.view','reservations.view','reservations.pay','finance.view','finance.manage','requests.view','requests.manage','reports.view','support.view'])
};
function pode(p){const s=rolePerms[CONTEXTO_USUARIO.role];return s&& (s.has('*')||s.has(p));}
function menuPermitido(id,p){if(id==='estoque'&&CONTEXTO_USUARIO.possui_estoque===false)return false;if(id==='servicos'&&CONTEXTO_USUARIO.servicos_extras===false)return false;return CONTEXTO_USUARIO.role==='admin'||pode(p)||id==='painel';}
function aplicarPermissoesDaTela(tab){
  const cfg={
    quartos:['rooms.manage',['form-quarto','form-lote']],categorias:['categories.manage',['form-cat']],
    reservas:['reservations.manage',['form-reserva']],servicos:['services.manage',['form-servico']],
    ordens:['orders.manage',['form-os']],equipe:['team.manage',['form-user']],
    estoque:['stock.manage',['form-estoque']],financeiro:['finance.manage',['form-fin']],
    integracoes:['integrations.manage',['form-integracoes']]
  }[tab];
  if(!cfg)return;
  const permitido=!!pode(cfg[0]);
  cfg[1].forEach(id=>{const form=document.getElementById(id);if(form&&form.closest('.card'))form.closest('.card').hidden=!permitido;});
  if(tab==='reservas'&&!pode('guests.manage')){const form=document.getElementById('form-hospede');if(form&&form.closest('.card'))form.closest('.card').hidden=true;}
  if(tab==='servicos'&&!pode('requests.manage')){const form=document.getElementById('form-pedido');if(form&&form.closest('.card'))form.closest('.card').hidden=true;}
}
function toast(msg,type=''){const host=document.getElementById('toast-host');const el=document.createElement('div');el.className='toast '+(type||'');el.textContent=msg;host.appendChild(el);setTimeout(()=>el.remove(),3500);}
function escapar(v){const d=document.createElement('div');d.textContent=v==null?'':String(v);return d.innerHTML;}
function moeda(v){return 'R$ '+Number(v||0).toFixed(2).replace('.',',');}
function dataHora(v){if(!v)return '-';try{return new Date(v).toLocaleString('pt-BR');}catch(e){return v;}}
function badgeStatus(s){
  const x=String(s||'').toUpperCase();
  let cl='badge-neutral';
  if(['PAGO','ATIVA','CONCLUIDA','ENTREGUE','DISPONIVEL','ATIVO'].includes(x))cl='badge-ok';
  else if(['PENDENTE','TESTE','ABERTO','EM_PREPARO','EM_ANDAMENTO','RESERVADO'].includes(x))cl='badge-pending';
  else if(['SUSPENSA','SUSPENSO','CANCELADA','CANCELADO','BLOQUEADO','MANUTENCAO'].includes(x))cl='badge-danger';
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
  const menu=CONTEXTO_USUARIO.role==='platform_admin'
    ? [{id:'plataforma',icone:'SA',nome:'Administração SaaS',permissao:'platform'}]
    : menusTenant.filter(x=>menuPermitido(x.id,x.permissao));
  menu.forEach(item=>{
    const b=document.createElement('button');b.type='button';b.className='nav-btn';b.dataset.tab=item.id;
    b.innerHTML='<span class="nav-code">'+item.icone+'</span><span>'+escapar(item.nome)+'</span>';
    b.addEventListener('click',()=>switchTab(item.id));
    nav.appendChild(b);
  });
}
function tituloAba(tab){
  if(tab==='plataforma')return 'Administração do SaaS';
  const m=menusTenant.find(x=>x.id===tab);return m?m.nome:'Painel';
}
function switchTab(tab,registrar=true){
  const target=document.getElementById('tab-'+tab);
  if(!target)return;
  if(CONTEXTO_USUARIO.role!=='platform_admin' && tab!=='painel'){
    const m=menusTenant.find(x=>x.id===tab);
    if(m&&!menuPermitido(m.id,m.permissao)){toast('Seu perfil não possui acesso a esta área.','error');return;}
  }
  if(registrar&&abaAtual&&abaAtual!==tab)historicoAbas.push(abaAtual);
  abaAtual=tab;
  aplicarPermissoesDaTela(tab);
  document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));
  target.classList.add('active');
  document.querySelectorAll('.nav-btn').forEach(x=>x.classList.toggle('active',x.dataset.tab===tab));
  document.getElementById('page-title').textContent=tituloAba(tab);
  const hotel=CONTEXTO_USUARIO.hotel_nome;
  document.getElementById('page-subtitle').textContent=CONTEXTO_USUARIO.role==='platform_admin'?'Controle de clientes e assinaturas':(hotel||'Gestão operacional');
  document.getElementById('user-name').textContent=CONTEXTO_USUARIO.nome;
  document.getElementById('user-role').textContent=CONTEXTO_USUARIO.role_label;
  document.getElementById('hotel-name').textContent=hotel||'Sem hotel vinculado';
  if(CONTEXTO_USUARIO.role!=='platform_admin')registrarUsoModulo(tab);
  loadTab(tab).catch(e=>toast(e.message,'error'));
}
function registrarUsoModulo(module){jsonFetch('/api/telemetria/modulo',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({module})}).catch(()=>{});}
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
  const q=await jsonFetch('/api/quartos');
  const h=pode('guests.view')?await jsonFetch('/api/hospedes'):[];
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
    const acoes=pode('rooms.manage')?'<div class="row-actions"><button class="btn btn-secondary" onclick="editarQuarto('+q.id+')">Editar</button><button class="btn btn-danger" onclick="deletarQuarto('+q.id+')">Excluir</button></div>':'—';
    tr.innerHTML='<td><strong>'+escapar(q.numero)+'</strong></td><td>'+escapar(q.tipo)+'</td><td>'+moeda(q.preco_diaria)+'</td><td>'+badgeStatus(q.status)+'</td><td>'+acoes+'</td>';
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
function editarHospede(id){const h=state.hospedes.find(x=>x.id===id);if(!h)return;switchTab('reservas');document.getElementById('h-edit-id').value=id;document.getElementById('h-nome').value=h.nome;document.getElementById('h-doc').value=h.documento||'';document.getElementById('h-tel').value=h.telefone||'';document.getElementById('h-email').value=h.email||'';document.getElementById('h-obs').value=h.observacoes||'';document.getElementById('h-cancel').classList.remove('hidden');document.getElementById('h-submit').textContent='Salvar alterações';document.getElementById('hospede-form-title').textContent='Editar hóspede';}
document.getElementById('form-hospede').addEventListener('submit',async e=>{e.preventDefault();const id=document.getElementById('h-edit-id').value;const body={nome:document.getElementById('h-nome').value,documento:document.getElementById('h-doc').value,telefone:document.getElementById('h-tel').value,email:document.getElementById('h-email').value,observacoes:document.getElementById('h-obs').value};try{await jsonFetch(id?'/api/hospedes/'+id:'/api/hospedes',{method:id?'PUT':'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});toast(id?'Hóspede atualizado.':'Hóspede cadastrado.','success');limparHospedeForm();carregarHospedes();}catch(e){toast(e.message,'error');}});
document.getElementById('h-cancel').onclick=limparHospedeForm;

async function carregarCategorias(){state.faixas=await jsonFetch('/api/faixas_etarias')||[];preencherFaixas();const tb=document.getElementById('tabela-categorias');tb.innerHTML='';state.faixas.forEach(f=>{const tr=document.createElement('tr');tr.innerHTML='<td>'+escapar(f.nome)+'</td><td>'+f.idade_min+' a '+f.idade_max+'</td><td>'+moeda(f.valor_adicional)+'</td><td><div class="row-actions"><button class="btn btn-secondary" onclick="editarCategoria('+f.id+')">Editar</button><button class="btn btn-danger" onclick="excluirCategoria('+f.id+')">Excluir</button></div></td>';tb.appendChild(tr);});}
function limparCategoriaForm(){document.getElementById('form-cat').reset();document.getElementById('cat-edit-id').value='';document.getElementById('cat-adicional').value='0';document.getElementById('cat-cancel').classList.add('hidden');document.getElementById('cat-submit').textContent='Salvar categoria';document.getElementById('cat-form-title').textContent='Nova categoria de pessoa';}
function editarCategoria(id){const f=state.faixas.find(x=>x.id===id);if(!f)return;switchTab('categorias');document.getElementById('cat-edit-id').value=id;document.getElementById('cat-nome').value=f.nome;document.getElementById('cat-min').value=f.idade_min;document.getElementById('cat-max').value=f.idade_max;document.getElementById('cat-adicional').value=f.valor_adicional;document.getElementById('cat-cancel').classList.remove('hidden');document.getElementById('cat-submit').textContent='Salvar alterações';document.getElementById('cat-form-title').textContent='Editar categoria';}
async function excluirCategoria(id){if(!confirm('Excluir esta categoria?'))return;try{await jsonFetch('/api/faixas_etarias/'+id,{method:'DELETE'});toast('Categoria removida.','success');carregarCategorias();}catch(e){toast(e.message,'error');}}
document.getElementById('form-cat').addEventListener('submit',async e=>{e.preventDefault();const id=document.getElementById('cat-edit-id').value;const body={nome:document.getElementById('cat-nome').value,idade_min:parseInt(document.getElementById('cat-min').value,10),idade_max:parseInt(document.getElementById('cat-max').value,10),valor_adicional:parseFloat(document.getElementById('cat-adicional').value)};try{await jsonFetch(id?'/api/faixas_etarias/'+id:'/api/faixas_etarias',{method:id?'PUT':'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});toast(id?'Categoria atualizada.':'Categoria salva.','success');limparCategoriaForm();carregarCategorias();}catch(e){toast(e.message,'error');}});
document.getElementById('cat-cancel').onclick=limparCategoriaForm;

async function carregarReservas(){
  const [rows,quartos,hospedes]=await Promise.all([jsonFetch('/api/reservas'),jsonFetch('/api/quartos'),jsonFetch('/api/hospedes')]);
  const faixas=pode('categories.view')?await jsonFetch('/api/faixas_etarias'):[];
  state.reservas=rows||[];state.quartos=quartos||[];state.hospedes=hospedes||[];state.faixas=faixas||[];
  popularSelect('r-quarto-num',state.quartos.filter(x=>x.status!=='MANUTENCAO'),null,x=>x.numero+' — '+x.tipo,x=>x.numero);
  popularSelect('r-hospede-id',state.hospedes,null,x=>x.nome,x=>x.id);preencherFaixas();
  const tb=document.getElementById('tabela-reservas');tb.innerHTML='';
  if(!state.reservas.length){tb.innerHTML='<tr><td colspan="10" class="empty">Nenhuma reserva cadastrada.</td></tr>';return;}
  state.reservas.forEach(r=>{const tr=document.createElement('tr');const pagado=String(r.status_pagamento).toUpperCase()==='PAGO';const cancelada=String(r.status).toUpperCase()==='CANCELADA';const mov=r.checkout_realizado_em?'Check-out realizado':r.checkin_realizado_em?'Check-in realizado':'Pendente';const botaoMov=!cancelada&&!r.checkin_realizado_em?'<button class="btn btn-secondary" onclick="registrarMovimentacaoReserva('+r.id+',&quot;checkin&quot;)">Check-in</button>':!cancelada&&!r.checkout_realizado_em?'<button class="btn btn-secondary" onclick="registrarMovimentacaoReserva('+r.id+',&quot;checkout&quot;)">Check-out</button>':'';tr.innerHTML='<td>'+r.id+'<br><span class="small">'+escapar(r.canal_origem||'Direto')+'</span></td><td>'+escapar(r.hospede_nome||'Não informado')+'</td><td><strong>'+escapar(r.quarto_numero)+'</strong></td><td>'+escapar(r.check_in)+' até '+escapar(r.check_out)+'</td><td>'+r.diarias+'</td><td>'+moeda(r.valor_total)+'</td><td>'+badgeStatus(r.status_pagamento)+'</td><td>'+escapar(r.observacoes||'-')+'</td><td>'+escapar(mov)+'<br>'+botaoMov+'</td><td><div class="row-actions">'+(!cancelada?'<button class="btn btn-secondary" onclick="editarReserva('+r.id+')">Editar</button>':'')+(!cancelada?'<button class="btn '+(pagado?'btn-warning':'btn-success')+'" onclick="alterarPagamentoReserva('+r.id+','+(pagado?'false':'true')+')">'+(pagado?'Não pago':'Pagou')+'</button>':'')+(!cancelada?'<button class="btn btn-danger" onclick="cancelarReserva('+r.id+')">Cancelar</button>':'')+'</div></td>';tb.appendChild(tr);});
}
function alternarNovoHospedeReserva(){const box=document.getElementById('r-novo-hospede'),select=document.getElementById('r-hospede-id'),show=box.classList.contains('hidden');box.classList.toggle('hidden',!show);select.required=!show;document.getElementById('r-novo-nome').required=show;if(show)select.value='';}
function limparReservaForm(){document.getElementById('form-reserva').reset();document.getElementById('r-edit-id').value='';document.getElementById('r-novo-hospede').classList.add('hidden');document.getElementById('r-hospede-id').required=true;document.getElementById('r-novo-nome').required=false;document.getElementById('r-cancel').classList.add('hidden');document.getElementById('r-submit').textContent='Criar reserva';document.getElementById('reserva-form-title').textContent='Nova reserva';preencherFaixas();}
function editarReserva(id){const r=state.reservas.find(x=>x.id===id);if(!r)return;switchTab('reservas');document.getElementById('r-novo-hospede').classList.add('hidden');document.getElementById('r-hospede-id').required=true;document.getElementById('r-novo-nome').required=false;document.getElementById('r-edit-id').value=id;document.getElementById('r-hospede-id').value=r.hospede_id;document.getElementById('r-quarto-num').value=r.quarto_numero;document.getElementById('r-checkin').value=r.check_in;document.getElementById('r-checkout').value=r.check_out;document.getElementById('r-canal').value=r.canal_origem||'Direto';document.getElementById('r-observacoes').value=r.observacoes||'';document.getElementById('r-cancel').classList.remove('hidden');document.getElementById('r-submit').textContent='Salvar alterações';document.getElementById('reserva-form-title').textContent='Editar reserva #'+id;}
async function registrarMovimentacaoReserva(id,acao){try{const d=await jsonFetch('/api/reservas/'+id+'/movimentacao',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({acao})});toast(d.mensagem,'success');await carregarReservas();}catch(e){toast(e.message,'error');}}
async function alterarPagamentoReserva(id,pago){const forma=pago?(prompt('Forma de pagamento (PIX, cartão, dinheiro etc.):','PIX')||'Não informado'):'Não informado';if(pago&&!confirm('Confirmar que a reserva foi paga e lançar a entrada no caixa?'))return;if(!pago&&!confirm('Marcar a reserva como não paga e remover a entrada automática do caixa?'))return;try{await jsonFetch('/api/reservas/'+id+'/pagamento',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({status:pago?'PAGO':'PENDENTE',forma_pagamento:forma})});toast('Pagamento da reserva atualizado.','success');carregarReservas();}catch(e){toast(e.message,'error');}}
async function cancelarReserva(id){if(!confirm('Cancelar esta reserva? O pagamento automático, se houver, será retirado do caixa.'))return;try{await jsonFetch('/api/reservas/'+id+'/cancelar',{method:'PUT'});toast('Reserva cancelada.','success');carregarReservas();}catch(e){toast(e.message,'error');}}
document.getElementById('form-reserva').addEventListener('submit',async e=>{e.preventDefault();const id=document.getElementById('r-edit-id').value,novo=document.getElementById('r-novo-hospede').classList.contains('hidden')?null:{nome:document.getElementById('r-novo-nome').value,documento:document.getElementById('r-novo-doc').value,telefone:document.getElementById('r-novo-tel').value,email:document.getElementById('r-novo-email').value};const comps=[...document.querySelectorAll('.faixa-input')].map(x=>({faixa_id:parseInt(x.dataset.id,10),quantidade:parseInt(x.value||'0',10)}));const body={hospede_id:novo?null:(parseInt(document.getElementById('r-hospede-id').value,10)||null),novo_hospede:novo,quarto_numero:document.getElementById('r-quarto-num').value,check_in:document.getElementById('r-checkin').value,check_out:document.getElementById('r-checkout').value,canal_origem:document.getElementById('r-canal').value,observacoes:document.getElementById('r-observacoes').value,composicao:comps};try{const d=await jsonFetch(id?'/api/reservas/'+id:'/api/reservas',{method:id?'PUT':'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});toast((id?'Reserva atualizada. ':'Reserva criada. ')+moeda(d.valor_total),'success');limparReservaForm();await Promise.all([carregarReservas(),carregarHospedes()]);}catch(e){toast(e.message,'error');}});
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

async function carregarOrdens(){state.ordens=await jsonFetch('/api/ordens')||[];const tb=document.getElementById('tabela-os');tb.innerHTML='';if(!state.ordens.length){tb.innerHTML='<tr><td colspan="8" class="empty">Nenhuma ordem de serviço.</td></tr>';return;}state.ordens.forEach(o=>{const local='Quarto '+(o.quarto||'-')+(o.quarto_andar!==null&&o.quarto_andar!==undefined?' · '+o.quarto_andar+'º andar':'');const tr=document.createElement('tr');tr.innerHTML='<td>#'+o.id+'</td><td><strong>'+escapar(local)+'</strong></td><td>'+escapar(o.hospede_nome||'-')+'</td><td><strong>'+escapar(o.tipo)+'</strong><br><span class="small">'+escapar(o.descricao)+'</span></td><td>'+badgeStatus(o.prioridade)+'</td><td>'+escapar(o.responsavel_nome||'A definir')+(o.responsavel_telefone?'<br><span class="small">'+escapar(o.responsavel_telefone)+'</span>':'')+'</td><td>'+badgeStatus(o.status)+'</td><td><div class="row-actions"><button class="btn btn-secondary" onclick="editarOrdem('+o.id+')">Editar</button><button class="btn btn-primary" onclick="avancarOrdem('+o.id+')">Status</button><button class="btn btn-danger" onclick="excluirOrdem('+o.id+')">Excluir</button></div></td>';tb.appendChild(tr);});
  await carregarUsuariosParaOS();
}
async function carregarUsuariosParaOS(){if(CONTEXTO_USUARIO.role==='platform_admin')return;try{const rows=await jsonFetch('/api/usuarios');state.usuarios=rows||[];popularSelect('os-responsavel',state.usuarios.filter(x=>x.ativo),'A definir',x=>x.nome+' — '+x.role_label+(x.telefone?' · WhatsApp':'')+(x.whatsapp_notificacoes?' ✓':' ⚠'),x=>x.id);}catch(e){state.usuarios=[];}}
function limparOsForm(){document.getElementById('form-os').reset();document.getElementById('os-edit-id').value='';document.getElementById('os-cancel').classList.add('hidden');document.getElementById('os-submit').textContent='Criar OS';document.getElementById('os-form-title').textContent='Nova ordem de serviço';}
function editarOrdem(id){const o=state.ordens.find(x=>x.id===id);if(!o)return;switchTab('ordens');document.getElementById('os-edit-id').value=id;document.getElementById('os-quarto').value=o.quarto_id;document.getElementById('os-hospede').value=o.hospede_id||'';document.getElementById('os-tipo').value=o.tipo;document.getElementById('os-prioridade').value=o.prioridade;document.getElementById('os-responsavel').value=o.responsavel_id||'';document.getElementById('os-desc').value=o.descricao;document.getElementById('os-cancel').classList.remove('hidden');document.getElementById('os-submit').textContent='Salvar alterações';document.getElementById('os-form-title').textContent='Editar OS #'+id;}
async function avancarOrdem(id){const s=prompt('Novo status: PENDENTE, EM_ANDAMENTO, CONCLUIDA ou CANCELADA','CONCLUIDA');if(!s)return;try{await jsonFetch('/api/ordens/'+id+'/status',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({status:s})});toast('Status da OS atualizado.','success');carregarOrdens();}catch(e){toast(e.message,'error');}}
async function excluirOrdem(id){if(!confirm('Excluir esta OS?'))return;try{await jsonFetch('/api/ordens/'+id,{method:'DELETE'});toast('OS removida.','success');carregarOrdens();}catch(e){toast(e.message,'error');}}
document.getElementById('form-os').addEventListener('submit',async e=>{e.preventDefault();const id=document.getElementById('os-edit-id').value;const body={quarto_id:parseInt(document.getElementById('os-quarto').value,10),hospede_id:document.getElementById('os-hospede').value||null,tipo:document.getElementById('os-tipo').value,prioridade:document.getElementById('os-prioridade').value,responsavel_id:document.getElementById('os-responsavel').value||null,descricao:document.getElementById('os-desc').value};try{const d=await jsonFetch(id?'/api/ordens/'+id:'/api/ordens',{method:id?'PUT':'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});const wa=d.notificacao_whatsapp;if(!id&&wa){const mensagens={enviada:' Aviso enviado ao funcionário por WhatsApp.',nao_configurada:' Configure a WhatsApp Cloud API no servidor para ativar avisos.',destinatario_nao_configurado:' Cadastre o telefone e a autorização do funcionário para avisos.',telefone_invalido:' Confira o telefone do funcionário com DDI e DDD.',sem_responsavel:' Atribua um funcionário para enviar o aviso.'};toast((d.mensagem||'OS criada.')+(mensagens[wa.status]||''),wa.status==='enviada'?'success':'info');}else toast(id?'OS atualizada.':'OS criada.','success');limparOsForm();carregarOrdens();}catch(e){toast(e.message,'error');}});
document.getElementById('os-cancel').onclick=limparOsForm;

async function carregarEquipe(){if(CONTEXTO_USUARIO.role!=='admin')return;state.usuarios=await jsonFetch('/api/usuarios')||[];const tb=document.getElementById('tabela-equipe');tb.innerHTML='';state.usuarios.forEach(u=>{const wa=(u.telefone?escapar(u.telefone):'Sem telefone')+(u.whatsapp_notificacoes?' · avisos ativos':'');const tr=document.createElement('tr');tr.innerHTML='<td>'+escapar(u.nome||u.username)+'</td><td>'+escapar(u.username)+'</td><td>'+escapar(u.role_label)+'</td><td>'+wa+'</td><td>'+escapar(dataHora(u.ultimo_login))+'</td><td>'+badgeStatus(u.ativo?'ATIVO':'BLOQUEADO')+'</td><td><div class="row-actions"><button class="btn btn-secondary" onclick="editarUsuario('+u.id+')">Editar</button>'+(u.ativo?'<button class="btn btn-danger" onclick="bloquearUsuario('+u.id+')">Bloquear</button>':'')+'</div></td>';tb.appendChild(tr);});}
function limparUsuarioForm(){document.getElementById('form-user').reset();document.getElementById('u-edit-id').value='';document.getElementById('u-username').disabled=false;document.getElementById('u-password').required=true;document.getElementById('u-ativo').value='1';document.getElementById('u-cancel').classList.add('hidden');document.getElementById('u-submit').textContent='Criar acesso';document.getElementById('user-form-title').textContent='Novo acesso';}
function editarUsuario(id){const u=state.usuarios.find(x=>x.id===id);if(!u)return;switchTab('equipe');document.getElementById('u-edit-id').value=id;document.getElementById('u-nome').value=u.nome||'';document.getElementById('u-username').value=u.username;document.getElementById('u-username').disabled=true;document.getElementById('u-role').value=u.role;document.getElementById('u-email').value=u.email||'';document.getElementById('u-telefone').value=u.telefone||'';document.getElementById('u-whatsapp-optin').checked=!!u.whatsapp_notificacoes;document.getElementById('u-password').value='';document.getElementById('u-password').required=false;document.getElementById('u-ativo').value=u.ativo?'1':'0';document.getElementById('u-cancel').classList.remove('hidden');document.getElementById('u-submit').textContent='Salvar alterações';document.getElementById('user-form-title').textContent='Editar acesso';}
async function bloquearUsuario(id){if(!confirm('Bloquear este acesso?'))return;try{await jsonFetch('/api/usuarios/'+id,{method:'DELETE'});toast('Usuário bloqueado.','success');carregarEquipe();}catch(e){toast(e.message,'error');}}
document.getElementById('form-user').addEventListener('submit',async e=>{e.preventDefault();const id=document.getElementById('u-edit-id').value;const body={nome:document.getElementById('u-nome').value,username:document.getElementById('u-username').value,role:document.getElementById('u-role').value,email:document.getElementById('u-email').value,telefone:document.getElementById('u-telefone').value,whatsapp_notificacoes:document.getElementById('u-whatsapp-optin').checked,ativo:document.getElementById('u-ativo').value==='1',password:document.getElementById('u-password').value};try{await jsonFetch(id?'/api/usuarios/'+id:'/api/usuarios',{method:id?'PUT':'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});toast(id?'Acesso atualizado.':'Acesso criado.','success');limparUsuarioForm();carregarEquipe();}catch(e){toast(e.message,'error');}});
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

function dataLocalISO(d){return d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0')+'-'+String(d.getDate()).padStart(2,'0');}
function prepararPeriodoRelatorio(){const modo=document.getElementById('rel-periodo').value,hoje=new Date();hoje.setHours(12,0,0,0);let ini=new Date(hoje),fim=new Date(hoje);if(modo==='ontem'){ini.setDate(ini.getDate()-1);fim=new Date(ini);}else if(modo==='7dias')ini.setDate(ini.getDate()-6);else if(modo==='mes')ini=new Date(hoje.getFullYear(),hoje.getMonth(),1,12);else if(modo==='personalizado'){document.getElementById('rel-datas-personalizadas').classList.remove('hidden');if(!document.getElementById('rel-inicio').value)document.getElementById('rel-inicio').value=dataLocalISO(ini);if(!document.getElementById('rel-fim').value)document.getElementById('rel-fim').value=dataLocalISO(fim);return;}document.getElementById('rel-datas-personalizadas').classList.add('hidden');document.getElementById('rel-inicio').value=dataLocalISO(ini);document.getElementById('rel-fim').value=dataLocalISO(fim);}
function desenharGraficoOcupacao(rows){const el=document.getElementById('grafico-ocupacao');if(!rows||!rows.length){el.textContent='Sem reservas para exibir.';return;}const w=700,h=230,p=28,vals=rows.map(x=>Number(x.ocupacao)||0),max=Math.max(100,...vals),pts=vals.map((v,i)=>`${p+(rows.length===1?0:i*(w-2*p)/(rows.length-1))},${h-p-(v/max)*(h-2*p)}`).join(' ');const marca=rows.length>12?Math.ceil(rows.length/6):1;el.innerHTML='<svg viewBox="0 0 '+w+' '+h+'" role="img" aria-label="Evolução da ocupação"><line x1="'+p+'" y1="'+(h-p)+'" x2="'+(w-p)+'" y2="'+(h-p)+'" stroke="#d7dee8"/><line x1="'+p+'" y1="'+p+'" x2="'+p+'" y2="'+(h-p)+'" stroke="#d7dee8"/><polyline points="'+pts+'" fill="none" stroke="#1f4f8f" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>'+rows.filter((_,i)=>i%marca===0||i===rows.length-1).map((x,i)=>'<text x="'+(p+(rows.length===1?0:rows.indexOf(x)*(w-2*p)/(rows.length-1)))+'" y="'+(h-5)+'" text-anchor="middle" fill="#667085" font-size="11">'+x.data.slice(5)+'</text>').join('')+'</svg><div class="metric-note">Média do período: '+(vals.reduce((a,b)=>a+b,0)/vals.length).toFixed(1)+'%</div>';}
function desenharGraficoOrigem(rows){const el=document.getElementById('grafico-origem'),cores=['#1f4f8f','#12a594','#f59e0b','#a855f7','#ef4444','#64748b','#0ea5e9'],total=(rows||[]).reduce((a,x)=>a+Number(x.total||0),0);if(!total){el.textContent='Sem reservas cadastradas nesse período.';return;}let acc=0;const stops=rows.map((x,i)=>{const start=acc;acc+=Number(x.total||0)/total*100;return cores[i%cores.length]+' '+start+'% '+acc+'%';}).join(',');el.innerHTML='<div class="origin-layout"><div class="donut" style="background:conic-gradient('+stops+')"><div>'+total+'<small>reservas</small></div></div><div class="legend">'+rows.map((x,i)=>'<div><i style="background:'+cores[i%cores.length]+'"></i>'+escapar(x.canal)+' — '+x.total+' ('+(Number(x.total)/total*100).toFixed(0)+'%)</div>').join('')+'</div></div>';}
async function carregarRelatorios(){
  if(!document.getElementById('rel-inicio').value||!document.getElementById('rel-fim').value)prepararPeriodoRelatorio();
  const ini=document.getElementById('rel-inicio').value,fim=document.getElementById('rel-fim').value;if(!ini||!fim){toast('Escolha as datas do relatório.','error');return;}
  const d=await jsonFetch('/api/relatorios?inicio='+encodeURIComponent(ini)+'&fim='+encodeURIComponent(fim));if(!d)return;
  const c=d.comparativo||{},delta=Number(c.variacao_ocupacao||0),deltaTexto=(delta>=0?'↑ ':'↓ ')+Math.abs(delta).toFixed(1)+' p.p. vs período anterior';
  const arr=[['Ocupação média',Number(d.taxa_ocupacao).toFixed(1)+'%',deltaTexto],['Receita no caixa',moeda(d.receita_total),(Number(c.variacao_receita_percentual||0)>=0?'↑ ':'↓ ')+Math.abs(Number(c.variacao_receita_percentual||0)).toFixed(1)+'% vs período anterior'],['Receita gerada',moeda(d.receita_gerada),'Diárias que ocorreram no período'],['A receber',moeda(d.receita_a_vencer),'Parte gerada ainda pendente'],['ADR',moeda(d.adr),'Receita gerada por diária ocupada'],['RevPAR',moeda(d.revpar),'Receita gerada por quarto disponível'],['Cancelamentos',d.cancelamentos,'Reservas canceladas no período'],['Sem check-in hoje',d.no_show,d.no_show_percentual+'% das chegadas previstas'],['Ticket extra por hóspede',moeda(d.ticket_medio_hospede),'Consumo pago além da hospedagem']];
  document.getElementById('relatorio-metricas').innerHTML=arr.map(x=>'<div class="metric"><div class="metric-label">'+escapar(x[0])+'</div><div class="metric-value">'+escapar(x[1])+'</div><div class="metric-note">'+escapar(x[2])+'</div></div>').join('');
  const ops=[['Check-ins previstos',d.checkins_previstos],['Check-ins realizados',d.checkins_realizados],['Check-outs previstos',d.checkouts_previstos],['Check-outs realizados',d.checkouts_realizados],['Hóspedes in-house',d.hospedes_inhouse]];document.getElementById('relatorio-operacao').innerHTML=ops.map(x=>'<div class="metric"><div class="metric-label">'+x[0]+'</div><div class="metric-value">'+x[1]+'</div></div>').join('');
  desenharGraficoOcupacao(d.ocupacao_serie);desenharGraficoOrigem(d.origem_reservas);
  document.getElementById('tabela-previsao').innerHTML=(d.previsao_ocupacao||[]).map(x=>'<div class="forecast-row"><span>'+new Date(x.data+'T12:00:00').toLocaleDateString('pt-BR',{weekday:'short',day:'2-digit',month:'2-digit'})+'</span><div class="forecast-bar"><i style="width:'+Math.max(0,Math.min(100,Number(x.ocupacao)))+'%"></i></div><strong>'+Number(x.ocupacao).toFixed(0)+'%</strong><small>'+x.quartos+'/'+d.total_quartos+' quartos</small></div>').join('')||'Sem quartos cadastrados.';
  document.getElementById('tabela-adr-categoria').innerHTML=(d.adr_categoria||[]).map(x=>'<tr><td>'+escapar(x.categoria)+'</td><td>'+x.diarias+'</td><td>'+moeda(x.receita)+'</td><td>'+moeda(x.adr)+'</td></tr>').join('')||'<tr><td colspan="4" class="empty">Sem diárias no período.</td></tr>';
}
document.getElementById('rel-periodo').addEventListener('change',()=>{prepararPeriodoRelatorio();if(document.getElementById('rel-periodo').value!=='personalizado')carregarRelatorios();});
document.getElementById('rel-inicio').addEventListener('change',()=>{if(document.getElementById('rel-periodo').value==='personalizado')carregarRelatorios();});document.getElementById('rel-fim').addEventListener('change',()=>{if(document.getElementById('rel-periodo').value==='personalizado')carregarRelatorios();});
async function carregarPainel(){
  const el=document.getElementById('tab-painel');
  const atalhos=[['reservas','Abrir reservas'],['servicos','Abrir pedidos'],['ordens','Abrir ordens de serviço']].filter(([id])=>menuPermitido(id,(menusTenant.find(x=>x.id===id)||{}).permissao));
  el.innerHTML=`<div class="metrics" id="painel-metrics"></div><div class="card"><div class="card-header"><div><h2 class="card-title">Operação</h2><p class="card-help">Atalhos disponíveis para o seu perfil.</p></div></div><div class="toolbar">${atalhos.map(([id,nome])=>'<button class="btn btn-secondary" onclick="switchTab(\''+id+'\')">'+escapar(nome)+'</button>').join('')}</div></div>`;
  const metrics=document.getElementById('painel-metrics');
  metrics.innerHTML='<div class="metric"><div class="metric-label">Painel</div><div class="metric-value">Carregando…</div></div>';
  let d,s;
  if(!pode('reports.view')){
    try{
      const quartos=await jsonFetch('/api/quartos')||[];
      const ordens=pode('orders.view')?(await jsonFetch('/api/ordens')||[]):[];
      metrics.innerHTML=[['Quartos cadastrados',quartos.length],['Ordens abertas',ordens.filter(x=>!['CONCLUIDA','CANCELADA'].includes(String(x.status||'').toUpperCase())).length]].map(x=>'<div class="metric"><div class="metric-label">'+escapar(x[0])+'</div><div class="metric-value">'+escapar(x[1])+'</div></div>').join('');
    }catch(e){const aviso=document.createElement('div');aviso.className='notice danger';aviso.textContent='Não foi possível carregar os indicadores operacionais: '+e.message;el.insertBefore(aviso,metrics);}
    return;
  }
  try{d=await jsonFetch('/api/relatorios');s=CONTEXTO_USUARIO.role==='admin'?await jsonFetch('/api/assinatura'):null;}
  catch(e){const aviso=document.createElement('div');aviso.className='notice danger';aviso.textContent='Não foi possível carregar os indicadores: '+e.message;el.insertBefore(aviso,metrics);return;}
  if(!d)return;
  const m=[['Quartos',d.total_quartos],['Ocupados',d.quartos_ocupados],['Ocupação',Number(d.taxa_ocupacao).toFixed(2)+'%'],['Receita paga',moeda(d.receita_total)]];
  document.getElementById('painel-metrics').innerHTML=m.map(x=>'<div class="metric"><div class="metric-label">'+escapar(x[0])+'</div><div class="metric-value">'+escapar(x[1])+'</div></div>').join('');
  if(s){const card=document.createElement('div');card.className='notice '+(s.ativo?'success':'danger');card.textContent='Plano '+(s.plano_nome||'-')+' | status: '+(s.status||'-')+(s.periodo_fim?' | validade: '+s.periodo_fim:'');document.getElementById('tab-painel').insertBefore(card,document.getElementById('painel-metrics'));}
}
async function carregarIntegracoes(){
  const d=await jsonFetch('/api/integracoes');if(!d)return;
  document.getElementById('int-booking').value=d.booking_url||'';document.getElementById('int-airbnb').value=d.airbnb_url||'';document.getElementById('int-expedia').value=d.expedia_url||'';document.getElementById('int-hoteis').value=d.hoteis_url||'';document.getElementById('int-site').value=d.website_url||'';document.getElementById('int-whatsapp').value=d.whatsapp_telefone||'';document.getElementById('int-whatsapp-status').textContent=d.whatsapp_api_configurada?'Credenciais da WhatsApp Cloud API presentes no servidor; o envio só será confirmado ao disparar uma mensagem.':'WhatsApp Cloud API pendente: adicione as credenciais do servidor para ativar os avisos.';document.getElementById('int-api-status').textContent='Geoapify Geocoding (servidor): '+(d.geoapify_api_configurada?'chave presente':'pendente')+' · Geoapify Static Maps (navegador): '+(d.geoapify_maps_configurada?'chave presente':'pendente')+' · Asaas: '+(d.asaas_configurada?'credenciais presentes':'pendente de credenciais')+' (presença verificada; conexão não testada)';document.getElementById('int-maps-url').value=d.maps_url||'';document.getElementById('int-maps-nome').value=d.maps_nome||'';document.getElementById('int-place-id').value=d.maps_place_id||'';document.getElementById('int-endereco').value=d.endereco||'';document.getElementById('int-lat').value=d.latitude??'';document.getElementById('int-lng').value=d.longitude??'';document.getElementById('int-webhook-url').value=d.webhook_asaas_url||'';renderMapa(d.maps_embed_url);
  await carregarPlanos();
}
async function carregarPlanos(){state.planos=await jsonFetch('/api/planos')||[];const el=document.getElementById('saas-plano');el.innerHTML=state.planos.map(p=>'<option value="'+p.id+'">'+escapar(p.nome)+' — '+moeda(p.preco_mensal)+'/mês</option>').join('');state.sub=await jsonFetch('/api/assinatura');if(state.sub){document.getElementById('saas-status').value=state.sub.status||'';document.getElementById('saas-fim').value=state.sub.periodo_fim||state.sub.trial_ate||'';}}
async function contratarPlano(){const id=parseInt(document.getElementById('saas-plano').value,10);try{const d=await jsonFetch('/api/assinatura/checkout',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({plano_id:id})});if(d&&d.checkout_url)window.open(d.checkout_url,'_blank','noopener,noreferrer');else toast(d.mensagem||'Checkout criado.','success');}catch(e){toast(e.message,'error');}}
document.getElementById('form-integracoes').addEventListener('submit',async e=>{e.preventDefault();const body={booking_url:document.getElementById('int-booking').value.trim(),airbnb_url:document.getElementById('int-airbnb').value.trim(),expedia_url:document.getElementById('int-expedia').value.trim(),hoteis_url:document.getElementById('int-hoteis').value.trim(),website_url:document.getElementById('int-site').value.trim(),whatsapp_telefone:document.getElementById('int-whatsapp').value.trim(),maps_url:document.getElementById('int-maps-url').value.trim(),maps_nome:document.getElementById('int-maps-nome').value.trim(),maps_place_id:document.getElementById('int-place-id').value.trim(),endereco:document.getElementById('int-endereco').value.trim(),latitude:document.getElementById('int-lat').value||null,longitude:document.getElementById('int-lng').value||null};try{const d=await jsonFetch('/api/integracoes',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});toast(d.mensagem,'success');renderMapa(d.integracao?.maps_embed_url||null);}catch(e){toast(e.message,'error');}});
async function pesquisarGeoapify(){const q=(document.getElementById('int-maps-nome').value||document.getElementById('int-endereco').value||'').trim();if(q.length<3){toast('Informe nome ou endereço.','error');return;}try{const d=await jsonFetch('/api/integracoes/maps/pesquisar',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({q})});const box=document.getElementById('resultado-maps');box.innerHTML='';(d.resultados||[]).forEach(p=>{const b=document.createElement('button');b.type='button';b.className='btn btn-secondary';b.style.margin='4px';b.textContent=(p.nome||'Local')+' — '+(p.endereco||'');b.onclick=()=>{document.getElementById('int-maps-nome').value=p.nome||'';document.getElementById('int-place-id').value=p.id||'';document.getElementById('int-endereco').value=p.endereco||'';document.getElementById('int-lat').value=p.latitude??'';document.getElementById('int-lng').value=p.longitude??'';document.getElementById('int-maps-url').value=p.maps_url||'';};box.appendChild(b);});if(!(d.resultados||[]).length)box.textContent='Nenhum local encontrado.';}catch(e){toast(e.message,'error');}}
function renderMapa(url){const box=document.getElementById('mapa-hotel');box.innerHTML='';if(!url){box.className='notice info';box.textContent='Mapa disponível após configurar GEOAPIFY_MAPS_API_KEY no .env e informar coordenadas.';return;}box.className='';const img=document.createElement('img');img.src=url;img.alt='Mapa da localização do hotel';img.width=800;img.height=350;img.style.width='100%';img.style.height='auto';img.style.borderRadius='12px';img.loading='lazy';box.appendChild(img);const credit=document.createElement('small');credit.textContent='Mapa © Geoapify · dados © OpenStreetMap contributors';box.appendChild(credit);}
function preencherWhatsApp(){document.getElementById('wa-msg').value=document.getElementById('wa-template').value;}
document.getElementById('wa-template').addEventListener('change',preencherWhatsApp);
preencherWhatsApp();
function enviarWhatsApp(){const tel=document.getElementById('wa-tel').value.replace(/\\D/g,'');if(tel.length<10){toast('Informe um telefone válido com DDD.','error');return;}window.open('https://wa.me/'+tel+'?text='+encodeURIComponent(document.getElementById('wa-msg').value),'_blank','noopener,noreferrer');}

async function carregarPlataformaUsuarios(){
  const aviso=document.getElementById('plataforma-usuarios-aviso');
  const tb=document.getElementById('tabela-plataforma-usuarios');
  aviso.className='notice info';aviso.textContent='Atualizando usuários...';tb.innerHTML='';
  try{
    const usuarios=await jsonFetch('/api/platform/usuarios');
    if(!usuarios||!usuarios.length){aviso.className='notice info';aviso.textContent='Nenhum usuário de hotel cadastrado.';return;}
    usuarios.forEach(u=>{
      const tr=document.createElement('tr');
      tr.innerHTML='<td>'+escapar(u.nome||u.username)+'<div class="small">'+escapar(u.username)+'</div></td><td>'+escapar(u.email||'-')+'</td><td>'+escapar(u.hotel_nome||'Sem hotel')+'</td><td>'+escapar(u.role)+'</td><td>'+escapar(dataHora(u.ultimo_login))+'</td><td>'+badgeStatus(Number(u.ativo)?'ATIVO':'SUSPENSO')+'</td><td></td>';
      const botao=document.createElement('button');botao.type='button';botao.className='btn '+(Number(u.ativo)?'btn-danger':'btn-success');botao.textContent=Number(u.ativo)?'Suspender':'Reativar';
      botao.addEventListener('click',()=>alternarStatusUsuario(u.id,!Number(u.ativo)));
      tr.lastElementChild.appendChild(botao);tb.appendChild(tr);
    });
    aviso.className='notice success';aviso.textContent=usuarios.length+' usuário(s) encontrado(s).';
  }catch(e){aviso.className='notice danger';aviso.textContent=e.message;}
}
async function carregarPlataformaMetricas(){
  const box=document.getElementById('plataforma-metricas'),saude=document.getElementById('plataforma-saude');
  try{
    const d=await jsonFetch('/api/platform/metricas');
    const itens=[['MRR',moeda(d.mrr),'Assinaturas ativas'],['ARR',moeda(d.arr),'MRR × 12'],['Clientes',d.clientes,'Hotéis cadastrados'],['Em teste',d.em_teste,'Assinaturas de avaliação'],['Inadimplentes',d.inadimplentes,'Período vencido'],['Onboardings',d.onboardings_30d,'Novos hotéis em 30 dias'],['Sem configuração',d.onboarding_sem_quartos,'Hotéis ainda sem quartos cadastrados'],['Churn estimado',d.churn_estimado_30d_percentual+'%','Cancelamentos registrados nos últimos 30 dias'],['LTV / CAC',d.ltv_cac===null?'Configure SAAS_CAC_ESTIMADO':d.ltv_cac+'×',d.ltv_estimado===null?'Sem histórico suficiente para estimar LTV':'LTV estimado: '+moeda(d.ltv_estimado)],['Reservas no mês',d.reservas_mes,'Check-ins hoje: '+d.checkins_hoje],['Check-outs hoje',d.checkouts_hoje,'Quartos: '+d.quartos_cadastrados],['Falhas de webhook',d.webhooks_com_erro_30d,'Últimos 30 dias'],['Chamados abertos',d.tickets_abertos,'Aguardando acompanhamento'],['SLA 1ª resposta',d.sla_media_primeira_resposta_horas===null?'Sem respostas ainda':d.sla_media_primeira_resposta_horas+' h','Média histórica dos chamados respondidos']];
    box.innerHTML=itens.map(x=>'<div class="metric"><div class="metric-label">'+escapar(x[0])+'</div><div class="metric-value">'+escapar(x[1])+'</div><div class="metric-note">'+escapar(x[2])+'</div></div>').join('');
    const i=d.integracoes,infra=d.infra;const linha=(nome,ok)=>'<li>'+escapar(nome)+': <strong>'+escapar(ok?'configurado':'pendente')+'</strong></li>';
    saude.className='notice '+(infra.banco_responde?'success':'danger');saude.innerHTML='<strong>Banco:</strong> '+escapar(infra.banco)+' respondeu em '+escapar(infra.latencia_ms)+' ms. <strong>Asaas:</strong> '+(i.asaas_configurado?'credenciais presentes; pagamento confirmado por webhook':'pendente de credenciais/URL pública')+'.<ul>'+linha('Geoapify Geocoding (servidor)',i.geoapify_configurado)+linha('Geoapify Static Maps',i.geoapify_maps_configurado)+linha('WhatsApp Cloud API',i.whatsapp_configurado)+'</ul><p>Booking.com, Airbnb e Expedia não estão conectados por API nesta instalação; o painel mostra acesso às extranets. A conexão direta exige credenciais, autorização e, conforme o canal, habilitação de parceiro.</p>';
    const mod=document.getElementById('plataforma-modulos');mod.innerHTML=(d.uso_modulos_30d||[]).length?d.uso_modulos_30d.map(x=>'<div>'+escapar(x.module)+': <strong>'+escapar(x.acessos)+'</strong> acessos</div>').join(''):'Nenhum acesso registrado nos últimos 30 dias.';
  }catch(e){box.innerHTML='<div class="notice danger">'+escapar(e.message)+'</div>';}
}
async function carregarTicketsPlataforma(){
  const box=document.getElementById('tickets-plataforma-aviso'),tb=document.getElementById('tabela-tickets-plataforma');if(!box||!tb)return;
  try{const rows=await jsonFetch('/api/platform/tickets');tb.innerHTML='';if(!rows.length){box.className='notice info';box.textContent='Nenhum chamado recebido.';return;}
    rows.forEach(t=>{const tr=document.createElement('tr');const primeira=t.primeira_resposta_em?dataHora(t.primeira_resposta_em):'Pendente';tr.innerHTML='<td><strong>'+escapar(t.hotel_nome)+'</strong><div>'+escapar(t.assunto)+'</div><div class="small">'+escapar((t.mensagens||[]).map(m=>m.autor_role+': '+m.mensagem).join(' · '))+'</div></td><td>'+escapar(t.prioridade)+'</td><td>'+escapar(t.status)+'</td><td>'+escapar(dataHora(t.criado_em))+'</td><td>'+escapar(primeira)+'</td><td></td>';const b=document.createElement('button');b.className='btn btn-primary';b.textContent='Responder / atualizar';b.onclick=async()=>{const resposta=prompt('Resposta ao hotel (deixe vazio para apenas mudar o status):');if(resposta===null)return;const status=prompt('Status: ABERTO, EM_ATENDIMENTO, AGUARDANDO_CLIENTE ou RESOLVIDO',t.status==='ABERTO'?'EM_ATENDIMENTO':t.status);if(!status)return;try{await jsonFetch('/api/platform/tickets/'+t.id,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({resposta,status})});await carregarTicketsPlataforma();await carregarPlataformaMetricas();}catch(e){toast(e.message,'error');}};tr.lastElementChild.appendChild(b);tb.appendChild(tr);});box.className='notice success';box.textContent=rows.length+' chamado(s). A primeira resposta registrada fica visível para acompanhar o SLA.';
  }catch(e){box.className='notice danger';box.textContent=e.message;}
}
async function carregarChamados(){const box=document.getElementById('suporte-lista');if(!box)return;try{const rows=await jsonFetch('/api/suporte/tickets');box.innerHTML='';if(!rows.length){box.className='notice info';box.textContent='Você ainda não abriu chamados.';return;}rows.forEach(t=>{const card=document.createElement('div');card.className='notice '+(t.status==='RESOLVIDO'?'success':'info');const head=document.createElement('strong');head.textContent='#'+t.id+' · '+t.assunto+' · '+t.status;card.appendChild(head);(t.mensagens||[]).forEach(m=>{const p=document.createElement('p');p.textContent=m.autor_role+': '+m.mensagem;card.appendChild(p);});if(t.status!=='RESOLVIDO'){const b=document.createElement('button');b.className='btn btn-secondary';b.textContent='Responder';b.onclick=async()=>{const mensagem=prompt('Escreva sua resposta (mínimo 8 caracteres):');if(!mensagem)return;try{await jsonFetch('/api/suporte/tickets',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ticket_id:t.id,mensagem})});await carregarChamados();}catch(e){toast(e.message,'error');}};card.appendChild(b);}box.appendChild(card);});}catch(e){box.className='notice danger';box.textContent=e.message;}}
async function abrirChamado(){const assunto=document.getElementById('suporte-assunto').value,mensagem=document.getElementById('suporte-mensagem').value,prioridade=document.getElementById('suporte-prioridade').value;try{await jsonFetch('/api/suporte/tickets',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({assunto,mensagem,prioridade})});document.getElementById('suporte-assunto').value='';document.getElementById('suporte-mensagem').value='';toast('Chamado aberto.','success');await carregarChamados();}catch(e){toast(e.message,'error');}}
async function alternarStatusUsuario(id,ativo){
  const acao=ativo?'reativar':'suspender';
  if(!confirm('Confirma '+acao+' o acesso deste usuário?'))return;
  try{await jsonFetch('/api/platform/usuarios/'+id+'/status',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({ativo})});toast(ativo?'Acesso reativado.':'Acesso suspenso.','success');await carregarPlataformaUsuarios();}
  catch(e){toast(e.message,'error');}
}
async function carregarPlataforma(){
  const aviso=document.getElementById('plataforma-aviso');const tb=document.getElementById('tabela-plataforma');aviso.className='notice info';aviso.textContent='Atualizando clientes...';
  try{
    const [hotels,plans]=await Promise.all([jsonFetch('/api/platform/hoteis'),jsonFetch('/api/planos')]);state.planos=plans||[];tb.innerHTML='';await carregarPlataformaMetricas();
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
    await carregarPlataformaUsuarios();
    await carregarTicketsPlataforma();
  }catch(e){aviso.className='notice danger';aviso.textContent=e.message;}
}
async function alternarBloqueio(id,bloquear){const motivo=bloquear?(prompt('Motivo do bloqueio:','Pagamento pendente')||'Pagamento pendente'):'';if(bloquear&&!confirm('Bloquear o acesso deste hotel?'))return;if(!bloquear&&!confirm('Liberar o acesso deste hotel?'))return;try{await jsonFetch('/api/platform/hoteis/'+id+'/bloqueio',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({bloqueado:bloquear,motivo})});toast(bloquear?'Hotel bloqueado.':'Hotel liberado.','success');carregarPlataforma();}catch(e){toast(e.message,'error');}}
async function salvarAssinaturaPlataforma(id){const plano_id=parseInt(document.getElementById('plan-'+id).value,10),status=document.getElementById('status-'+id).value,dias=parseInt(document.getElementById('dias-'+id).value,10);try{await jsonFetch('/api/platform/assinaturas/'+id,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({plano_id,status,dias})});toast('Assinatura atualizada.','success');carregarPlataforma();}catch(e){toast(e.message,'error');}}

async function loadTab(tab){
  if(CONTEXTO_USUARIO.role==='platform_admin'){if(tab==='plataforma')await carregarPlataforma();return;}
  if(tab==='painel')await carregarPainel();
  else if(tab==='quartos'){await carregarQuartos();}
  else if(tab==='categorias'){await carregarCategorias();}
  else if(tab==='reservas'){await carregarReservas();await carregarHospedes();}
  else if(tab==='servicos'){await carregarBase();await carregarServicos();await carregarPedidos();}
  else if(tab==='ordens'){await carregarBase();await carregarOrdens();}
  else if(tab==='equipe'){await carregarEquipe();}
  else if(tab==='estoque'){await carregarEstoque();}
  else if(tab==='financeiro'){await carregarFinanceiro();}
  else if(tab==='relatorios'){await carregarRelatorios();}
  else if(tab==='integracoes'){await carregarIntegracoes();}
  else if(tab==='suporte'){await carregarChamados();}
  else if(tab==='whatsapp'){preencherWhatsApp();}
}

const painelHospedes=document.getElementById('painel-hospedes-reserva');
painelHospedes.classList.add('reserva-hospedes');
document.getElementById('tab-reservas').appendChild(painelHospedes);
renderNav();
switchTab(primeiraAba,false);
