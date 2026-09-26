# Ford Inteligência Competitiva

**Ford FIAP 2026 · Desafio 01 — Inteligência Competitiva Automotiva**
**Sprint 3 — Cybersecurity: Pipeline DevSecOps, Hardening e Observabilidade**

![Python](https://img.shields.io/badge/Python-3.13-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.136-009688?logo=fastapi&logoColor=white)
![Tests](https://img.shields.io/badge/tests-37%20passed-brightgreen)
![Coverage](https://img.shields.io/badge/coverage-96%25-brightgreen)
![Vulnerabilities](https://img.shields.io/badge/known%20vulnerabilities-0-brightgreen)
![License](https://img.shields.io/badge/license-academic-lightgrey)

API que consulta especificações técnicas padronizadas de veículos a partir de marca, modelo e versão, construída como estudo de caso de **hardening de segurança e DevSecOps**: autenticação robusta, RBAC, proteção contra abuso, criptografia com rotação de chaves, observabilidade completa e um pipeline de CI/CD com 5 gates de segurança obrigatórios.

**Relatório técnico completo da Sprint 3** (pipeline, hardening, observabilidade e compliance): [`docs/Sprint3_Cybersecurity_Ford_FIAP.docx`](docs/Sprint3_Cybersecurity_Ford_FIAP.docx)

---

## Sumário

- [Visão geral](#-visão-geral)
- [Controles de segurança](#️-controles-de-segurança)
- [Stack técnica](#-stack-técnica)
- [Estrutura do projeto](#-estrutura-do-projeto)
- [Instalação](#-instalação)
- [Configuração (obrigatória)](#-configuração-obrigatória)
- [Como executar](#-como-executar)
- [Testes e varreduras de segurança](#-testes-e-varreduras-de-segurança)
- [Observabilidade](#-observabilidade-prometheus--grafana)
- [Pipeline CI/CD](#-pipeline-cicd)
- [Exemplos de uso da API](#-exemplos-de-uso-da-api)
- [Evidências](#-evidências)
- [Equipe](#-equipe)

---

## Visão geral

```
┌──────────────┐      HTTPS/JSON       ┌──────────────────┐
│   Frontend   │  ───────────────────► │    API FastAPI    │
│ (HTML/JS/CSS)│  ◄─────────────────── │  (autenticação,    │
└──────────────┘      Bearer JWT       │   RBAC, busca)     │
                                        └─────────┬──────────┘
                                                  │ métricas /metrics
                                                  ▼
                                        ┌──────────────────┐
                                        │ Prometheus +     │
                                        │ Grafana          │
                                        └──────────────────┘
```

O usuário se autentica (`/login`) e recebe um token JWT de curta duração. Com o token, consulta especificações técnicas de um veículo (`/buscar`); o veículo de validação obrigatória do desafio é a **Ford Ranger Raptor**. Perfis `analista` e `admin` têm permissões distintas, aplicadas no servidor.

## Controles de segurança

| Área | Controle implementado |
|---|---|
| **Segredos** | Somente via variáveis de ambiente; a API falha na inicialização (fail-fast) se algum estiver ausente ou fraco |
| **Senhas** | Hash Argon2id, comparação em tempo constante, sem enumeração de usuários |
| **Sessão (JWT)** | HS256, claims obrigatórios (`iss`/`aud`/`exp`/`iat`/`nbf`/`jti`), expira em 15 min, revogação via `/logout` |
| **Autorização** | RBAC verificado no servidor (`analista` / `admin`) em toda rota sensível |
| **Anti-abuso** | Rate limit por IP + bloqueio de conta após 5 tentativas de login inválidas |
| **Validação de entrada** | Allow-list de caracteres, campos extras rejeitados, sem eco do payload no erro |
| **Dados em repouso** | Criptografia Fernet com suporte a rotação de chaves (`MultiFernet`) |
| **Observabilidade** | Logs estruturados em JSON com `request_id` e e-mails anonimizados; métricas Prometheus |
| **HTTP** | Cabeçalhos de segurança (CSP, X-Frame-Options, HSTS), CORS restrito, Swagger desligado em produção |
| **Frontend** | Sem credenciais pré-preenchidas, sem `innerHTML` (anti-XSS), CSP própria |
| **Infraestrutura** | Imagem Docker sem `pip`/`setuptools`/`wheel`, executando com usuário não-root |
| **Pipeline** | GitHub Actions: Gitleaks, Bandit, pip-audit, pytest, Trivy — deploy condicionado a todos passarem |

**Resultado mensurável** (antes → depois do hardening): Bandit **3 → 0** ocorrências · pip-audit **37 → 0** vulnerabilidades conhecidas · testes automatizados **0 → 37** (96% de cobertura). Detalhes completos no [relatório da Sprint 3](docs/Sprint3_Cybersecurity_Ford_FIAP.docx).

## Stack técnica

| Camada | Tecnologia |
|---|---|
| API | Python 3.13, FastAPI, Uvicorn |
| Autenticação | PyJWT, Argon2 (`argon2-cffi`) |
| Criptografia | `cryptography` (Fernet) |
| Rate limiting | SlowAPI |
| Observabilidade | `prometheus-client`, Prometheus, Grafana |
| Frontend | HTML, CSS, JavaScript (vanilla) |
| Testes | pytest, pytest-cov, httpx |
| Segurança (CI) | Gitleaks, Bandit, pip-audit, Trivy |
| Containerização | Docker |
| CI/CD | GitHub Actions, Dependabot |

## Estrutura do projeto

```
ford-fiap-2026/
├── main.py                     # API (FastAPI)
├── requirements.txt            # Dependências de produção
├── requirements-dev.txt        # + testes e ferramentas de segurança
├── Dockerfile
├── .env.example                # Modelo de variáveis de ambiente
├── frontend/                   # Interface web de testes
│   ├── index.html
│   ├── script.js
│   └── style.css
├── tests/                      # 37 testes de segurança automatizados
│   ├── conftest.py
│   └── test_security.py
├── scripts/
│   └── simular_ataques.py      # Simula 6 cenários de ataque contra a API
├── monitoring/                 # Stack de observabilidade
│   ├── docker-compose.yml
│   ├── prometheus.yml
│   └── grafana/
├── docs/
│   └── Sprint3_Cybersecurity_Ford_FIAP.docx
├── evidencias/                 # Saídas reais das ferramentas (antes/depois)
├── prints/                     # Capturas de tela da versão anterior (baseline)
└── .github/
    ├── workflows/devsecops.yml # Pipeline DevSecOps
    └── dependabot.yml
```

## Instalação

```bash
git clone https://github.com/YujiSam/ford-fiap-2026.git
cd ford-fiap-2026
python -m venv venv
source venv/Scripts/activate      # Windows (Git Bash) | Linux/Mac: source venv/bin/activate
pip install -r requirements.txt
```

## Configuração (obrigatória)

```bash
cp .env.example .env
```

Gere os segredos e substitua cada `TROQUE_ME` no `.env`:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"                              # JWT_SECRET
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" # FERNET_KEYS
python -c "import secrets; print(secrets.token_urlsafe(32))"                              # METRICS_TOKEN
```

`ANALISTA_PASSWORD` e `ADMIN_PASSWORD` (mín. 12 caracteres) são definidas por você. **Nunca faça commit do `.env`.** Se algum desses valores for exposto acidentalmente (print de tela, log de terminal), gere novos e substitua — os antigos devem ser considerados comprometidos.

## Como executar

```bash
# Terminal 1 — API
uvicorn main:app --reload

# Terminal 2 — Frontend
cd frontend && python -m http.server 3000
```

- API: http://localhost:8000 (Swagger em `/docs`, desabilitado quando `ENV=production`)
- Frontend: http://localhost:3000

## Testes e varreduras de segurança

```bash
pip install -r requirements-dev.txt

python -m pytest tests -v --cov=main        # 37 testes de segurança, cobertura mínima 80%
bandit -r main.py                           # SAST
pip-audit -r requirements.txt               # SCA

# Simula ataques reais contra a API em execução e gera logs/métricas
python scripts/simular_ataques.py http://localhost:8000 SENHA_ANALISTA SENHA_ADMIN
```

## Observabilidade (Prometheus + Grafana)

```bash
cd monitoring
cp .env.monitoring.example .env    # preencha com o MESMO METRICS_TOKEN da API
docker compose up -d
```

- **Prometheus** — http://localhost:9090 (`Status → Targets` deve mostrar `ford-ic-api` como `UP`)
- **Grafana** — http://localhost:3001 (login `admin` / `admin` no primeiro acesso)

O dashboard **"Ford Inteligência Competitiva - Cybersecurity"** já vem provisionado, com painéis de requisições por status, eventos de segurança, tentativas de força bruta, tokens inválidos/revogados, latência e erros internos.

## Pipeline CI/CD

O workflow [`devsecops.yml`](.github/workflows/devsecops.yml) roda a cada push/PR na `main` (e semanalmente, agendado) com 6 etapas encadeadas — qualquer falha bloqueia o deploy:

`secret-scan (Gitleaks)` → `sast (Bandit)` → `sca (pip-audit)` → `test (pytest)` → `container-scan (Trivy)` → `deploy (GHCR)`

A branch `main` exige que os 5 checks de segurança passem antes de qualquer merge. O [`dependabot.yml`](.github/dependabot.yml) mantém dependências Python, GitHub Actions e a imagem Docker atualizadas semanalmente.

## Exemplos de uso da API

```bash
# Login
curl -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -d '{"usuario":"analista","senha":"SUA_SENHA"}'

# Busca autenticada
curl -X POST http://localhost:8000/buscar \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer SEU_TOKEN" \
  -d '{"marca":"Ford","modelo":"Ranger","versao":"Raptor"}'

# Logout (revoga o token)
curl -X POST http://localhost:8000/logout \
  -H "Authorization: Bearer SEU_TOKEN"
```

## Evidências

O [relatório completo da Sprint 3](docs/Sprint3_Cybersecurity_Ford_FIAP.docx) reúne e interpreta todas as evidências abaixo. Os arquivos brutos ficam versionados no repositório para consulta e auditoria independente:

| Pasta | Conteúdo | Uso |
|---|---|---|
| [`evidencias/`](evidencias) | Saída real das ferramentas de segurança, em texto puro, capturada antes e depois do hardening desta sprint (`bandit_antes.txt` / `bandit_depois.txt`, `pipaudit_antes_full.txt` / `pipaudit_depois.txt`), além dos logs JSON e da saída do script de simulação de ataques (`api_logs.jsonl`, `simulacao_saida.txt`, `metricas_eventos.txt`) | Comprovar, sem depender de captura de tela, os números citados no relatório (ex.: Bandit 3 → 0, pip-audit 37 → 0) |
| [`prints/`](prints) | Capturas de tela da versão anterior do projeto (Sprint passada), antes do hardening — inclui a tela de login com credenciais expostas e os logs em texto livre | Baseline de comparação "antes", referenciada no relatório junto às capturas equivalentes da versão atual |

## Equipe

| Integrante | RM |
|---|---|
| Gustavo Yuji Osugi | 555034 |
| Gustavo Viega | 555885 |
| Kaio Drago Lima Souza | 556095 |
| Vitor Rivas Cardoso | 556404 |
| Otavio Santos de Lima Ferrão | 556452 |

**Scrum Master:** Prof. Yan Coelho

---

<sub>Projeto acadêmico — Ford FIAP 2026. Uso educacional.</sub>
