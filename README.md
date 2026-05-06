# 🚗 Ford Inteligência Competitiva

## 📋 Sobre o Projeto

API desenvolvida para o desafio da Ford FIAP 2026, com foco em **Inteligência Competitiva Automotiva** e **Cybersecurity**.

A solução permite buscar especificações técnicas de veículos de forma padronizada, com autenticação JWT, criptografia de dados sensíveis e logs anonimizados.

---

## 🎯 Funcionalidades

| Funcionalidade | Descrição |
|----------------|-----------|
| 🔐 Autenticação JWT | Login com token válido por 2 horas |
| 🔍 Busca de veículos | Retorna especificações padronizadas |
| 🛡️ Sanitização de entrada | Proteção contra SQL Injection e XSS |
| 📝 Logs anonimizados | Emails são ocultados nos logs |
| 🔒 Criptografia | Dados sensíveis são criptografados |
| 📊 Histórico | Buscas registradas (acesso apenas admin) |
| 🎨 Frontend Web | Interface amigável para testes |

---

## 🛠️ Tecnologias Utilizadas

| Tecnologia | Versão | Para que serve |
|------------|--------|----------------|
| Python | 3.13+ | Linguagem principal |
| FastAPI | 0.136.1 | Framework web |
| PyJWT | 2.10.1 | Autenticação JWT |
| Cryptography | 45.0.7 | Criptografia de dados |
| Pydantic | 2.13.3 | Validação de dados |
| Uvicorn | 0.46.0 | Servidor ASGI |

---

## 📦 Instalação

### 1. Clone o repositório

```bash
git clone https://github.com/seu-usuario/ford-challenge.git
cd ford-challenge
```

### 2. Crie e ative o ambiente virtual

# Windows 

```bash
python -m venv venv
source venv/Scripts/activate
```

# Linux/Mac

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Instale as dependências

```bash
pip install -r requirements.txt
```

## 🚀 Como Executar

# Terminal 1 – API (Backend)

```bash
uvicorn main:app --reload
```

A API estará disponível em: http://localhost:8000

# Terminal 2 – Frontend

```bash
cd frontend
python -m http.server 3000
```

O frontend estará disponível em: http://localhost:3000

## 👥 Credenciais para Teste

| Usuário | Senha | Role | Permissões |
|---------|-------|------|-------------|
| `analista` | `123456` | analista | Buscar veículos, ver lista |
| `admin` | `admin123` | admin | Tudo do analista + histórico + testes criptografia |

## 📡 Exemplos de Requisições

### Login

```bash
curl -X POST "http://localhost:8000/login" \
  -H "Content-Type: application/json" \
  -d '{"usuario":"analista","senha":"123456"}'
```

```bash
curl -X POST "http://localhost:8000/buscar" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer SEU_TOKEN" \
  -d '{"marca":"Ford","modelo":"Ranger","versao":"Raptor"}'
```
