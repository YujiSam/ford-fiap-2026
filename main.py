"""
Ford Inteligência Competitiva — API
Sprint 3 · Cybersecurity (DevSecOps)

Controles de segurança implementados (ver documento da Sprint 3):
  * Segredos e chaves somente via variáveis de ambiente (fail-fast, sem valor default)
  * Senhas com hash Argon2id; comparação com tempo constante (anti user-enumeration)
  * JWT endurecido: alg fixo, iss/aud/exp/iat/nbf/jti obrigatórios, expiração curta, revogação (logout)
  * RBAC (analista / admin) aplicado no servidor
  * Validação por lista de permissão (allow-list) e rejeição de campos extras
  * Rate limit por IP + bloqueio temporário de conta (brute force / credential stuffing)
  * Criptografia Fernet com rotação de chaves (MultiFernet) para o histórico
  * Logs estruturados em JSON (sem senhas/tokens) + métricas Prometheus + X-Request-ID
  * Cabeçalhos de segurança, CORS restrito e mensagens de erro genéricas
"""
import contextvars
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sys
import time
import uuid
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import List, Optional

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from pydantic import BaseModel, ConfigDict, Field, field_validator
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

load_dotenv()

# ==================== CONFIGURAÇÃO (somente via ambiente) ====================
ENV = os.getenv("ENV", "dev").lower()
IS_PROD = ENV == "production"
SERVICE_NAME = "ford-ic-api"


class ConfigError(RuntimeError):
    """Configuração de segurança ausente ou fraca: a aplicação NÃO deve subir."""


def _segredo(nome: str, min_len: int) -> str:
    valor = os.getenv(nome, "")
    if len(valor) < min_len or valor.upper().startswith("TROQUE"):
        raise ConfigError(
            f"Variável {nome} ausente ou fraca (mínimo {min_len} caracteres). Veja .env.example"
        )
    return valor


JWT_SECRET = _segredo("JWT_SECRET", 32)  # HS256 exige chave >= 256 bits
JWT_ALGORITHM = "HS256"
JWT_ISSUER = "ford-ic-api"
JWT_AUDIENCE = "ford-ic-web"
ACCESS_TOKEN_MINUTES = int(os.getenv("ACCESS_TOKEN_MINUTES", "15"))
METRICS_TOKEN = _segredo("METRICS_TOKEN", 24)

try:
    # Primeira chave criptografa; todas descriptografam (rotação sem perda de dados)
    _fernets = [Fernet(k.strip()) for k in _segredo("FERNET_KEYS", 44).split(",") if k.strip()]
    cipher = MultiFernet(_fernets)
except (ValueError, TypeError) as exc:
    raise ConfigError("FERNET_KEYS inválida: use Fernet.generate_key() (separadas por vírgula)") from exc

CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(",") if o.strip()]

LOGIN_RATE = os.getenv("LOGIN_RATE", "10/minute")
BUSCA_RATE = os.getenv("BUSCA_RATE", "30/minute")
DEFAULT_RATE = os.getenv("DEFAULT_RATE", "120/minute")
MAX_FALHAS = 5          # tentativas inválidas por usuário...
JANELA_FALHAS = 300     # ...dentro desta janela (segundos) => bloqueio temporário

# ==================== LOGS ESTRUTURADOS (JSON) ====================
request_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")
_LOG_KEY = hashlib.sha256(b"log-pseudonym|" + JWT_SECRET.encode()).digest()


class JsonFormatter(logging.Formatter):
    """Uma linha JSON por evento: fácil de indexar (ELK/Loki) e imune a log injection (CWE-117)."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "service": SERVICE_NAME,
            "event": getattr(record, "event", record.getMessage()),
            "request_id": request_id_ctx.get(),
        }
        payload.update(getattr(record, "fields", {}) or {})
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)  # traceback só no log interno
        return json.dumps(payload, ensure_ascii=False, default=str)


logger = logging.getLogger("ford-api")
logger.setLevel(logging.INFO)
logger.propagate = False
if not logger.handlers:
    _h = logging.StreamHandler(sys.stdout)
    _h.setFormatter(JsonFormatter())
    logger.addHandler(_h)

# ==================== MÉTRICAS (Prometheus) ====================
HTTP_REQUESTS = Counter("ford_http_requests_total", "Requisições HTTP", ["method", "route", "status"])
HTTP_LATENCY = Histogram("ford_http_request_duration_seconds", "Latência HTTP", ["route"])
SECURITY_EVENTS = Counter("ford_security_events_total", "Eventos de segurança", ["event"])


def log_event(event: str, level: int = logging.INFO, **fields) -> None:
    """Registra evento de segurança/negócio (log JSON + contador Prometheus)."""
    SECURITY_EVENTS.labels(event=event).inc()
    logger.log(level, event, extra={"event": event, "fields": fields})


def pseudonimo(valor: str) -> str:
    """Identificador irreversível para correlacionar tentativas sem gravar o texto digitado (LGPD)."""
    return hmac.new(_LOG_KEY, valor.encode(), hashlib.sha256).hexdigest()[:12]


def anonimizar_email(email: str) -> str:
    if not email or "@" not in email:
        return "anonimo"
    local, dominio = email.split("@", 1)
    return f"*@{dominio}" if len(local) <= 1 else f"{local[0]}****@{dominio}"


def criptografar(dado: str) -> str:
    return cipher.encrypt(dado.encode()).decode() if dado else ""


def descriptografar(dado_cripto: str) -> str:
    return cipher.decrypt(dado_cripto.encode()).decode() if dado_cripto else ""


# ==================== APP ====================
app = FastAPI(
    title="Ford Inteligência Competitiva",
    version="4.0-devsecops",
    docs_url=None if IS_PROD else "/docs",      # Swagger fora do ar em produção (API9/A05)
    redoc_url=None if IS_PROD else "/redoc",
    openapi_url=None if IS_PROD else "/openapi.json",
)

limiter = Limiter(key_func=get_remote_address, default_limits=[DEFAULT_RATE])
app.state.limiter = limiter


async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    log_event("RATE_LIMIT_EXCEEDED", logging.WARNING, ip=get_remote_address(request),
              path=request.url.path, limit=str(exc.detail))
    return JSONResponse(status_code=429, headers={"Retry-After": "60"},
                        content={"detail": "Muitas requisições. Tente novamente em instantes."})


app.add_exception_handler(RateLimitExceeded, rate_limit_handler)


async def validation_handler(request: Request, exc: RequestValidationError):
    # Não devolve o valor enviado (evita reflexão de payload) e gera sinal de detecção
    erros = [{"loc": list(e.get("loc", [])), "msg": e.get("msg", "inválido")} for e in exc.errors()]
    log_event("VALIDATION_ERROR", logging.WARNING, ip=get_remote_address(request),
              path=request.url.path, campos=[".".join(map(str, e["loc"])) for e in erros])
    return JSONResponse(status_code=422, content={"detail": erros})


app.add_exception_handler(RequestValidationError, validation_handler)

_DOCS_PATHS = ("/docs", "/redoc", "/openapi.json")


@app.middleware("http")
async def seguranca_e_observabilidade(request: Request, call_next):
    rid = uuid.uuid4().hex[:16]
    request_id_ctx.set(rid)
    inicio = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:  # erro inesperado: log interno detalhado, resposta genérica (ASVS 7.4.1)
        logger.exception("erro não tratado", extra={"event": "UNHANDLED_ERROR", "fields": {"path": request.url.path}})
        SECURITY_EVENTS.labels(event="UNHANDLED_ERROR").inc()
        response = JSONResponse(status_code=500, content={"detail": "Erro interno", "request_id": rid})

    route = getattr(request.scope.get("route"), "path", "unmatched")
    HTTP_REQUESTS.labels(request.method, route, str(response.status_code)).inc()
    HTTP_LATENCY.labels(route).observe(time.perf_counter() - inicio)

    response.headers["X-Request-ID"] = rid
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    if not request.url.path.startswith(_DOCS_PATHS):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    if IS_PROD:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# Ordem: SlowAPI (interno) -> middleware acima -> CORS (mais externo)
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,          # allow-list explícita (ASVS 14.5.3)
    allow_credentials=False,             # usamos Bearer no header, não cookies
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
    max_age=600,
)

# ==================== MODELOS (validação por allow-list) ====================
TEXTO_RE = re.compile(r"[\w][\w .\-+/]{0,49}")
ATTR_RE = re.compile(r"[a-z0-9_\-]{1,30}")
USER_RE = re.compile(r"[A-Za-z0-9_.@\-]{1,50}")


class BuscaRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    marca: str = Field(..., min_length=1, max_length=50)
    modelo: str = Field(..., min_length=1, max_length=50)
    versao: str = Field(..., min_length=1, max_length=50)
    atributos: Optional[List[str]] = Field(default=None, max_length=20)

    @field_validator("marca", "modelo", "versao")
    @classmethod
    def texto_permitido(cls, v: str) -> str:
        if not TEXTO_RE.fullmatch(v):
            raise ValueError("caracteres não permitidos")
        return v

    @field_validator("atributos")
    @classmethod
    def atributos_permitidos(cls, v):
        if v is None:
            return v
        limpos = [a.strip().lower() for a in v]
        if not all(ATTR_RE.fullmatch(a) for a in limpos):
            raise ValueError("atributo inválido")
        return limpos


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    usuario: str = Field(..., min_length=1, max_length=50)
    senha: str = Field(..., min_length=1, max_length=128)

    @field_validator("usuario")
    @classmethod
    def usuario_permitido(cls, v: str) -> str:
        if not USER_RE.fullmatch(v):
            raise ValueError("usuário inválido")
        return v


class CriptoTesteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    dado: str = Field(..., min_length=1, max_length=200)


# ==================== DADOS ====================
DADOS_RANGER_RAPTOR = {
    "motor": "V6 3.0L Nano bi turbo",
    "potencia": "397cv @ 5650 RPM",
    "torque_max": "583 Nm @ 3500 RPM",
    "transmissao": "AT de 10 velocidades e paddle shifters",
    "tracao": "4WD",
    "amortecedores": 'Live Valve FOX Racing 2.5"',
    "0-100_kmh": "5.8s",
    "farois": "Matrix LED",
    "rodas_pneus": '17" com 285/70 R17 AT',
    "preco": "R$ 499.000",
}

# ==================== USUÁRIOS (hash Argon2id; senhas vêm do ambiente) ====================
ph = PasswordHasher()  # Argon2id, parâmetros padrão (RFC 9106 - perfil de baixo consumo)


def _usuario(env_senha: str, role: str, email: str) -> dict:
    return {"hash": ph.hash(_segredo(env_senha, 12)), "role": role, "email": email}  # ASVS 2.1.1 / 2.4.1


USUARIOS = {
    "analista": _usuario("ANALISTA_PASSWORD", "analista", "analista@ford.com"),
    "admin": _usuario("ADMIN_PASSWORD", "admin", "admin@ford.com"),
}
ROLES_VALIDAS = {u["role"] for u in USUARIOS.values()}
_DUMMY_HASH = ph.hash(secrets.token_urlsafe(16))  # equaliza o tempo quando o usuário não existe

HISTORICO: deque = deque(maxlen=1000)   # limita memória (API4: consumo irrestrito de recursos)
REVOGADOS: dict = {}                    # jti -> exp (tokens invalidados por logout)
FALHAS: dict = {}                       # usuario -> [timestamps de falhas]


def _verificar_senha(hash_ref: str, senha: str) -> bool:
    try:
        return ph.verify(hash_ref, senha)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def _falhas_recentes(chave: str) -> list:
    agora = time.time()
    lista = [t for t in FALHAS.get(chave, []) if agora - t < JANELA_FALHAS]
    if lista:
        FALHAS[chave] = lista
    else:
        FALHAS.pop(chave, None)
    return lista


def _bloqueio_restante(chave: str) -> int:
    """Segundos restantes de bloqueio (0 = livre). Vale também para usuários inexistentes (sem enumeração)."""
    lista = _falhas_recentes(chave)
    if len(lista) < MAX_FALHAS:
        return 0
    return max(1, int(JANELA_FALHAS - (time.time() - lista[0])))


def _registrar_falha(chave: str) -> None:
    if len(FALHAS) > 10_000:  # evita crescimento ilimitado por um atacante
        for k in list(FALHAS)[:5_000]:
            FALHAS.pop(k, None)
    FALHAS.setdefault(chave, []).append(time.time())


# ==================== JWT ====================
def criar_token(usuario: str, role: str) -> str:
    agora = datetime.now(timezone.utc)
    payload = {
        "sub": usuario,
        "role": role,
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": agora,
        "nbf": agora,
        "exp": agora + timedelta(minutes=ACCESS_TOKEN_MINUTES),
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


bearer = HTTPBearer(auto_error=False)


def _nao_autenticado(evento: str, request: Request) -> HTTPException:
    log_event(evento, logging.WARNING, ip=get_remote_address(request), path=request.url.path)
    return HTTPException(status_code=401, detail="Token inválido ou expirado",
                         headers={"WWW-Authenticate": "Bearer"})


def verificar_token(request: Request, creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer)):
    if creds is None or creds.scheme.lower() != "bearer":
        raise _nao_autenticado("TOKEN_MISSING", request)
    try:
        payload = jwt.decode(
            creds.credentials,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],                       # nunca aceitar "none" / troca de algoritmo
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
            options={"require": ["exp", "iat", "nbf", "sub", "iss", "aud", "jti"]},
            leeway=5,
        )
    except jwt.ExpiredSignatureError:
        raise _nao_autenticado("TOKEN_EXPIRED", request)
    except jwt.PyJWTError:
        raise _nao_autenticado("TOKEN_INVALID", request)

    agora = time.time()
    for jti in [j for j, exp in REVOGADOS.items() if exp < agora]:  # limpeza de revogados já expirados
        REVOGADOS.pop(jti, None)
    if payload["jti"] in REVOGADOS or payload.get("role") not in ROLES_VALIDAS or payload["sub"] not in USUARIOS:
        raise _nao_autenticado("TOKEN_REVOKED", request)
    return payload


def requer_role(role_necessaria: str):
    def dependencia(request: Request, payload=Depends(verificar_token)):
        if payload.get("role") != role_necessaria:
            log_event("ACCESS_DENIED", logging.WARNING, ip=get_remote_address(request), path=request.url.path,
                      user=anonimizar_email(USUARIOS[payload["sub"]]["email"]), role=payload.get("role"),
                      role_necessaria=role_necessaria)
            raise HTTPException(status_code=403, detail="Acesso negado")
        return payload
    return dependencia


# ==================== ROTAS ====================
@app.get("/")
def root():
    return {"mensagem": "API Ford", "status": "online", "versao": app.version}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/login")
@limiter.limit(LOGIN_RATE)
def login(request: Request, dados: LoginRequest):
    ip = get_remote_address(request)
    chave = dados.usuario.lower()

    restante = _bloqueio_restante(chave)
    if restante:
        log_event("LOGIN_BLOCKED", logging.WARNING, user_hash=pseudonimo(chave), ip=ip, retry_after=restante)
        raise HTTPException(status_code=429, detail="Muitas tentativas de login. Tente novamente mais tarde.",
                            headers={"Retry-After": str(restante)})

    usuario = USUARIOS.get(chave)
    senha_ok = _verificar_senha(usuario["hash"] if usuario else _DUMMY_HASH, dados.senha)
    if not (usuario and senha_ok):
        _registrar_falha(chave)
        log_event("LOGIN_FAILURE", logging.WARNING, user_hash=pseudonimo(chave), ip=ip)
        if _bloqueio_restante(chave):
            log_event("ACCOUNT_LOCKED", logging.ERROR, user_hash=pseudonimo(chave), ip=ip,
                      falhas=MAX_FALHAS, janela_s=JANELA_FALHAS)
        raise HTTPException(status_code=401, detail="Credenciais inválidas",
                            headers={"WWW-Authenticate": "Bearer"})

    FALHAS.pop(chave, None)
    token = criar_token(chave, usuario["role"])
    log_event("LOGIN_SUCCESS", user=anonimizar_email(usuario["email"]), role=usuario["role"], ip=ip)
    return {"access_token": token, "token_type": "bearer",  # nosec B105 - tipo do token, não é senha
            "role": usuario["role"],
            "expires_in": ACCESS_TOKEN_MINUTES * 60}


@app.post("/logout")
def logout(request: Request, payload=Depends(verificar_token)):
    REVOGADOS[payload["jti"]] = payload["exp"]
    log_event("LOGOUT", user=anonimizar_email(USUARIOS[payload["sub"]]["email"]), ip=get_remote_address(request))
    return {"mensagem": "Sessão encerrada"}


@app.post("/buscar")
@limiter.limit(BUSCA_RATE)
def buscar(request: Request, dados: BuscaRequest, payload=Depends(verificar_token)):
    email = USUARIOS[payload["sub"]]["email"]
    encontrado = (dados.marca.lower(), dados.modelo.lower(), dados.versao.lower()) == ("ford", "ranger", "raptor")
    log_event("SEARCH", user=anonimizar_email(email), ip=get_remote_address(request),
              veiculo=f"{dados.marca} {dados.modelo} {dados.versao}", encontrado=encontrado,
              n_atributos=len(dados.atributos or []))

    # Histórico criptografado em repouso (Fernet: AES-128-CBC + HMAC-SHA256)
    HISTORICO.append({
        "usuario": criptografar(payload["sub"]),
        "marca": criptografar(dados.marca),
        "modelo": criptografar(dados.modelo),
        "versao": criptografar(dados.versao),
        "timestamp": criptografar(datetime.now(timezone.utc).isoformat()),
    })

    if not encontrado:
        raise HTTPException(status_code=404, detail="Veículo não encontrado")
    resultado = dict(DADOS_RANGER_RAPTOR)
    if dados.atributos:
        return {a: resultado.get(a, "não disponível") for a in dados.atributos}
    return resultado


@app.get("/veiculos")
def listar_veiculos(payload=Depends(verificar_token)):
    return {"veiculos": ["Ford Ranger Raptor"]}


@app.get("/admin/historico")
def admin_historico(request: Request, limite: int = Query(50, ge=1, le=200),
                    payload=Depends(requer_role("admin"))):
    """Somente admin lê o histórico descriptografado (paginado e auditado)."""
    log_event("ADMIN_ACTION", acao="historico", user=anonimizar_email(USUARIOS[payload["sub"]]["email"]),
              ip=get_remote_address(request))
    itens = []
    for item in list(HISTORICO)[-limite:]:
        try:
            itens.append({k: descriptografar(v) for k, v in item.items()})
        except InvalidToken:
            log_event("DECRYPT_FAILURE", logging.ERROR)  # adulteração ou chave errada
    return {"total_buscas": len(HISTORICO), "retornados": len(itens), "historico": itens}


@app.post("/admin/teste-criptografia")
def teste_criptografia(request: Request, corpo: CriptoTesteRequest, payload=Depends(requer_role("admin"))):
    """POST com corpo (antes era GET com o dado na URL, que vaza em logs de acesso)."""
    log_event("ADMIN_ACTION", acao="teste-criptografia", user=anonimizar_email(USUARIOS[payload["sub"]]["email"]),
              ip=get_remote_address(request))
    cripto = criptografar(corpo.dado)
    decripto = descriptografar(cripto)
    return {"original": corpo.dado, "criptografado": cripto, "descriptografado": decripto,
            "funciona": corpo.dado == decripto}


@app.get("/metrics", include_in_schema=False)
def metrics(request: Request, creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer)):
    """Endpoint Prometheus protegido por token estático próprio (não é o JWT de usuário)."""
    if creds is None or not hmac.compare_digest(creds.credentials.encode(), METRICS_TOKEN.encode()):
        raise _nao_autenticado("METRICS_UNAUTHORIZED", request)
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


log_event("APP_STARTED", env=ENV, cors_origins=len(CORS_ORIGINS), access_token_min=ACCESS_TOKEN_MINUTES)
