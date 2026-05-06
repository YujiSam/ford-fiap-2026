let token = '';

async function fazerLogin() {
    const usuario = document.getElementById('usuario').value;
    const senha = document.getElementById('senha').value;

    if (!usuario || !senha) {
        alert('Preencha usuário e senha');
        return;
    }

    try {
        const response = await fetch('http://localhost:8000/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ usuario: usuario, senha: senha })
        });

        if (!response.ok) {
            const erro = await response.json();
            alert('Erro no login: ' + erro.detail);
            return;
        }

        const data = await response.json();
        token = data.access_token;
        
        document.getElementById('usuarioLogado').textContent = usuario;
        document.getElementById('loginSection').style.display = 'none';
        document.getElementById('buscaSection').style.display = 'block';
        
        limparResultado();
        
    } catch (error) {
        alert('Erro ao conectar com o servidor: ' + error.message);
    }
}

function fazerLogout() {
    token = '';
    document.getElementById('loginSection').style.display = 'block';
    document.getElementById('buscaSection').style.display = 'none';
    document.getElementById('usuario').value = 'analista';
    document.getElementById('senha').value = '123456';
    limparResultado();
}

async function buscarVeiculo() {
    if (!token) {
        alert('Faça login primeiro');
        return;
    }

    const marca = document.getElementById('marca').value;
    const modelo = document.getElementById('modelo').value;
    const versao = document.getElementById('versao').value;
    const atributosStr = document.getElementById('atributos').value;

    if (!marca || !modelo || !versao) {
        alert('Preencha marca, modelo e versão');
        return;
    }

    let atributos = null;
    if (atributosStr.trim()) {
        atributos = atributosStr.split(',').map(function(a) { return a.trim().toLowerCase(); });
    }

    const resultadoDiv = document.getElementById('resultado');
    resultadoDiv.innerHTML = '<div class="loading">⏳ Buscando dados...</div>';
    resultadoDiv.classList.add('show');

    try {
        const response = await fetch('http://localhost:8000/buscar', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + token
            },
            body: JSON.stringify({ marca: marca, modelo: modelo, versao: versao, atributos: atributos })
        });

        if (response.status === 401) {
            alert('Token expirado. Faça login novamente.');
            fazerLogout();
            return;
        }

        if (!response.ok) {
            const erro = await response.json();
            mostrarErro(erro.detail || 'Erro na busca');
            return;
        }

        const data = await response.json();
        mostrarResultado(data);

    } catch (error) {
        mostrarErro('Erro ao conectar com o servidor: ' + error.message);
    }
}

function mostrarResultado(data) {
    const resultadoDiv = document.getElementById('resultado');
    
    if (Object.keys(data).length === 0) {
        resultadoDiv.innerHTML = '<div class="erro">⚠️ Nenhum dado encontrado</div>';
        return;
    }

    let html = '<h3>📋 Especificações Técnicas</h3>';
    html += '<table class="resultado-table">';
    
    for (var chave in data) {
        if (data.hasOwnProperty(chave)) {
            var valor = data[chave];
            
            var chaveTraduzida = '';
            if (chave === 'motor') chaveTraduzida = 'Motor';
            else if (chave === 'potencia') chaveTraduzida = 'Potência';
            else if (chave === 'torque_max') chaveTraduzida = 'Torque Máximo';
            else if (chave === 'transmissao') chaveTraduzida = 'Transmissão';
            else if (chave === 'tracao') chaveTraduzida = 'Tração';
            else if (chave === 'amortecedores') chaveTraduzida = 'Amortecedores';
            else if (chave === '0-100_kmh') chaveTraduzida = '0-100 km/h';
            else if (chave === 'farois') chaveTraduzida = 'Faróis';
            else if (chave === 'rodas_pneus') chaveTraduzida = 'Rodas e Pneus';
            else if (chave === 'preco') chaveTraduzida = 'Preço';
            else chaveTraduzida = chave;
            
            html += '<tr>';
            html += '<td>' + chaveTraduzida + '</td>';
            html += '<td>' + valor + '</td>';
            html += '</tr>';
        }
    }
    
    html += '</table>';
    resultadoDiv.innerHTML = html;
}

function mostrarErro(mensagem) {
    const resultadoDiv = document.getElementById('resultado');
    resultadoDiv.innerHTML = '<div class="erro">❌ ' + mensagem + '</div>';
}

function limparResultado() {
    const resultadoDiv = document.getElementById('resultado');
    resultadoDiv.innerHTML = '';
    resultadoDiv.classList.remove('show');
}

document.addEventListener('DOMContentLoaded', function() {
    const campos = ['usuario', 'senha', 'marca', 'modelo', 'versao', 'atributos'];
    for (var i = 0; i < campos.length; i++) {
        var id = campos[i];
        var input = document.getElementById(id);
        if (input) {
            input.addEventListener('keypress', function(e, id) {
                if (e.key === 'Enter') {
                    if (this.id === 'usuario' || this.id === 'senha') {
                        fazerLogin();
                    } else {
                        buscarVeiculo();
                    }
                }
            }.bind(input, id));
        }
    }
});