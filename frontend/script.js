'use strict';
const API_URL = 'http://localhost:8000';
let token = '';   // somente em memória (não usa localStorage: reduz o impacto de XSS)

const $ = (id) => document.getElementById(id);
const ROTULOS = {
    motor: 'Motor', potencia: 'Potência', torque_max: 'Torque Máximo', transmissao: 'Transmissão',
    tracao: 'Tração', amortecedores: 'Amortecedores', '0-100_kmh': '0-100 km/h', farois: 'Faróis',
    rodas_pneus: 'Rodas e Pneus', preco: 'Preço'
};

// Toda saída usa textContent (nunca innerHTML) => sem XSS mesmo se a API devolver conteúdo malicioso
function mostrarMensagem(el, texto, classe) {
    el.replaceChildren();
    const div = document.createElement('div');
    div.className = classe;
    div.textContent = texto;
    el.appendChild(div);
}

function detalheDoErro(erro) {
    if (Array.isArray(erro.detail)) return 'Dados inválidos: verifique os campos informados.';
    return erro.detail || 'Erro na requisição';
}

async function fazerLogin() {
    const usuario = $('usuario').value.trim();
    const senha = $('senha').value;
    const erroEl = $('loginErro');
    erroEl.hidden = true;
    if (!usuario || !senha) { erroEl.textContent = 'Preencha usuário e senha'; erroEl.hidden = false; return; }
    try {
        const resp = await fetch(API_URL + '/login', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ usuario: usuario, senha: senha })
        });
        if (!resp.ok) {
            erroEl.textContent = detalheDoErro(await resp.json().catch(() => ({})));
            erroEl.hidden = false;
            return;
        }
        token = (await resp.json()).access_token;
        $('senha').value = '';
        $('usuarioLogado').textContent = usuario;
        $('loginSection').hidden = true;
        $('buscaSection').hidden = false;
        limparResultado();
    } catch (e) {
        erroEl.textContent = 'Não foi possível conectar ao servidor';
        erroEl.hidden = false;
    }
}

async function fazerLogout() {
    if (token) {   // revoga o token no servidor (best effort)
        fetch(API_URL + '/logout', { method: 'POST', headers: { Authorization: 'Bearer ' + token } }).catch(() => {});
    }
    token = '';
    $('usuario').value = '';
    $('senha').value = '';
    $('loginSection').hidden = false;
    $('buscaSection').hidden = true;
    limparResultado();
}

async function buscarVeiculo() {
    if (!token) return;
    const marca = $('marca').value.trim(), modelo = $('modelo').value.trim(), versao = $('versao').value.trim();
    const res = $('resultado');
    res.classList.add('show');
    if (!marca || !modelo || !versao) { mostrarMensagem(res, 'Preencha marca, modelo e versão', 'erro'); return; }
    const attrs = $('atributos').value.split(',').map((a) => a.trim().toLowerCase()).filter(Boolean);
    mostrarMensagem(res, '⏳ Buscando dados...', 'loading');
    try {
        const resp = await fetch(API_URL + '/buscar', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token },
            body: JSON.stringify({ marca: marca, modelo: modelo, versao: versao, atributos: attrs.length ? attrs : null })
        });
        if (resp.status === 401) { await fazerLogout(); $('loginErro').textContent = 'Sessão expirada. Entre novamente.'; $('loginErro').hidden = false; return; }
        if (resp.status === 429) { mostrarMensagem(res, 'Muitas requisições. Aguarde um instante.', 'erro'); return; }
        if (!resp.ok) { mostrarMensagem(res, '❌ ' + detalheDoErro(await resp.json().catch(() => ({}))), 'erro'); return; }
        mostrarResultado(await resp.json());
    } catch (e) {
        mostrarMensagem(res, '❌ Não foi possível conectar ao servidor', 'erro');
    }
}

function mostrarResultado(data) {
    const res = $('resultado');
    res.replaceChildren();
    const titulo = document.createElement('h3');
    titulo.textContent = '📋 Especificações Técnicas';
    const tabela = document.createElement('table');
    tabela.className = 'resultado-table';
    Object.keys(data).forEach((chave) => {
        const tr = document.createElement('tr');
        const th = document.createElement('td'); th.textContent = ROTULOS[chave] || chave;
        const td = document.createElement('td'); td.textContent = String(data[chave]);
        tr.append(th, td);
        tabela.appendChild(tr);
    });
    res.append(titulo, tabela);
}

function limparResultado() {
    const res = $('resultado');
    res.replaceChildren();
    res.classList.remove('show');
}

document.addEventListener('DOMContentLoaded', () => {
    $('btnLogin').addEventListener('click', fazerLogin);
    $('btnLogout').addEventListener('click', fazerLogout);
    $('btnBuscar').addEventListener('click', buscarVeiculo);
    $('btnLimpar').addEventListener('click', limparResultado);
    ['usuario', 'senha'].forEach((id) => $(id).addEventListener('keydown', (e) => { if (e.key === 'Enter') fazerLogin(); }));
    ['marca', 'modelo', 'versao', 'atributos'].forEach((id) => $(id).addEventListener('keydown', (e) => { if (e.key === 'Enter') buscarVeiculo(); }));
});
